"""OpenAI-compatible gateway (FastAPI layer).

Point any OpenAI SDK client (or a LangChain / LlamaIndex RAG) at this service
by changing `base_url`. The security logic lives in `pipeline.Gateway`; this
module only handles HTTP, upstream calls and audit records.
"""

from __future__ import annotations

import hmac
import re
import time
import uuid
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from . import __version__
from .audit import AuditLog
from .config import Action, FailMode, Policy, Settings
from .pii import Pseudonymizer
from .pii.factory import build_detectors
from .pii.vault import InMemoryVault
from .pipeline import DetectionFailure, Gateway, Prepared

_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def _checked_id(value: str | None, default: str, name: str) -> str:
    if value is None:
        return default
    if not _ID_RE.fullmatch(value):
        raise HTTPException(400, f"invalid {name}")
    return value


def create_app(
    settings: Settings | None = None,
    policy: Policy | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    detectors: list | None = None,
) -> FastAPI:
    settings = settings or Settings()
    policy = policy or Policy.load(settings.policy_path)
    policy = policy.model_copy(deep=True)
    if settings.ner_backend is not None:
        policy.ner.backend = settings.ner_backend
    if settings.external_model is not None:
        if not settings.external_model.strip() or "external" not in policy.upstreams:
            raise RuntimeError("SOVGATE_EXTERNAL_MODEL requires a model and external upstream")
        policy.upstreams["external"].model = settings.external_model
    if policy.verifier.require_address_manifest and policy.fail_mode != FailMode.CLOSED:
        raise RuntimeError("address manifest verification requires fail-closed policy")
    if policy.verifier.require_address_manifest and not settings.api_keys:
        raise RuntimeError("address manifests require authenticated clients (SOVGATE_API_KEYS)")
    if len(settings.hmac_secret) < 16:
        raise RuntimeError("SOVGATE_HMAC_SECRET must be set (min. 16 characters)")

    pseudo = Pseudonymizer(
        detectors=detectors if detectors is not None else build_detectors(policy),
        secret=settings.hmac_secret.encode(),
        vault=InMemoryVault(settings.vault_ttl_seconds),
    )
    gateway = Gateway(policy, pseudo)
    audit = AuditLog(settings.audit_path)
    client = httpx.AsyncClient(transport=transport, timeout=120)

    app = FastAPI(title="Sovereign LLM Gateway", version=__version__)
    app.state.gateway = gateway
    app.state.audit = audit

    @app.middleware("http")
    async def identify(request: Request, call_next):
        # Lets a client recognise a gateway, e.g. to refuse it where only a model on the
        # same machine is acceptable (privasoc's local-only residual pass).
        response = await call_next(request)
        response.headers["X-Sovgate-Version"] = __version__
        return response

    def tenant_for(authorization: str | None, x_tenant_id: str | None) -> str:
        """Tenant from the API key when keys are configured, else from the header."""
        if not settings.api_keys:
            return _checked_id(x_tenant_id, "default", "tenant id")
        token = (authorization or "").removeprefix("Bearer ").strip()
        tenant = next((t for k, t in settings.api_keys.items() if hmac.compare_digest(k, token)), None)
        if tenant is None:
            raise HTTPException(401, "missing or unknown API key")
        if x_tenant_id is not None and x_tenant_id != tenant:
            raise HTTPException(403, "X-Tenant-Id does not match the API key")
        return tenant

    def base_record(p: Prepared, request_id: str, tenant: str, session: str) -> dict[str, Any]:
        # Never put raw text in the audit trail: counts and decisions only.
        return {
            "request_id": request_id,
            "tenant": tenant,
            "session_id": session,
            "action": p.decision.action.value,
            "upstream": p.decision.upstream,
            "sensitivity": p.decision.sensitivity.value,
            "entities": p.entity_counts,
            "injection_rules": p.verdict.rules,
            "scan_scope": p.scan_scope,
            "spotlighted": p.spotlighted,
            "tools_stripped": p.decision.strip_tools,
            "detection_failed": p.detection_failed,
        }

    def prepare_or_fail(body: dict[str, Any], tenant: str, session: str, request_id: str) -> Prepared:
        try:
            return gateway.prepare(body, tenant, session)
        except DetectionFailure as exc:
            audit.append(
                {"request_id": request_id, "tenant": tenant, "status": "detector_error", "error": str(exc)}
            )
            raise HTTPException(503, "entity detection unavailable; request refused (fail-closed)") from exc

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/v1/models")
    async def models(
        authorization: str | None = Header(default=None),
        x_tenant_id: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """OpenAI-style model list: the configured upstream models (clients check it)."""
        tenant_for(authorization, x_tenant_id)
        return {
            "object": "list",
            "data": [
                {"id": up.model, "object": "model", "owned_by": f"sovgate:{name}"}
                for name, up in policy.upstreams.items()
            ],
        }

    @app.post("/v1/inspect")
    async def inspect(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
        x_tenant_id: str | None = Header(default=None),
    ):
        """Dry run: show exactly what would leave the perimeter, without calling any model."""
        tenant = tenant_for(authorization, x_tenant_id)
        session = f"inspect-{uuid.uuid4()}"
        p = prepare_or_fail(body, tenant, session, session)
        pseudo.vault.purge(p.vault_key)
        return {
            "decision": {
                "action": p.decision.action.value,
                "upstream": p.decision.upstream,
                "sensitivity": p.decision.sensitivity.value,
                "reasons": p.decision.reasons,
                "tools_stripped": p.decision.strip_tools,
            },
            "entities": [{"type": s.entity_type, "source": s.source} for s in p.spans],
            "injection": {"flagged": p.verdict.flagged, "rules": p.verdict.rules, "scope": p.scan_scope},
            "spotlighted_segments": p.spotlighted,
            "outbound": p.outbound,
        }

    @app.post("/v1/chat/completions")
    async def chat_completions(
        body: dict[str, Any],
        authorization: str | None = Header(default=None),
        x_session_id: str | None = Header(default=None),
        x_tenant_id: str | None = Header(default=None),
    ):
        # With SOVGATE_API_KEYS set, the tenant comes from the authenticated key.
        if body.get("stream"):
            raise HTTPException(400, "streaming is not supported yet (see ROADMAP)")
        tenant = tenant_for(authorization, x_tenant_id)
        session = _checked_id(x_session_id, str(uuid.uuid4()), "session id")
        request_id = str(uuid.uuid4())
        started = time.perf_counter()

        p = prepare_or_fail(body, tenant, session, request_id)
        record = base_record(p, request_id, tenant, session)

        if p.decision.action == Action.BLOCK or p.decision.upstream is None:
            audit.append({**record, "status": "blocked"})
            # Entity types and counts only, never values: the client uses them to learn
            # what its own pseudonymisation missed.
            raise HTTPException(
                403,
                {
                    "error": "blocked by policy",
                    "reasons": p.decision.reasons,
                    "entities": p.entity_counts,
                    "injection_rules": p.verdict.rules,
                },
            )

        upstream = policy.upstreams[p.decision.upstream]
        outbound = {**p.outbound, "model": upstream.model}
        headers = {"Content-Type": "application/json"}
        if upstream.api_key:
            headers["Authorization"] = f"Bearer {upstream.api_key}"
        try:
            resp = await client.post(
                f"{upstream.base_url.rstrip('/')}/chat/completions", json=outbound, headers=headers
            )
        except httpx.HTTPError as exc:
            audit.append({**record, "status": "upstream_error", "error": type(exc).__name__})
            raise HTTPException(502, "upstream unavailable") from exc

        payload = resp.json()
        if resp.status_code >= 400:
            audit.append({**record, "status": "upstream_error", "http_status": resp.status_code})
            return JSONResponse(payload, status_code=resp.status_code)

        payload = gateway.restore(payload, p)
        usage = payload.get("usage") or {}
        audit.append(
            {
                **record,
                "status": "ok",
                "model": upstream.model,
                "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                "prompt_tokens": usage.get("prompt_tokens"),
                "completion_tokens": usage.get("completion_tokens"),
            }
        )
        out_headers = {
            "X-Sovgate-Action": p.decision.action.value,
            "X-Sovgate-Upstream": p.decision.upstream,
            "X-Sovgate-Request-Id": request_id,
        }
        if p.verdict.flagged:
            out_headers["X-Sovgate-Injection"] = ",".join(p.verdict.rules)
        return JSONResponse(payload, headers=out_headers)

    return app

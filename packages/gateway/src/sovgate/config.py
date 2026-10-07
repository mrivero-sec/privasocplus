"""Policy and runtime configuration."""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class Sensitivity(str, Enum):
    PUBLIC = "public"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @property
    def rank(self) -> int:
        return {"public": 0, "confidential": 1, "restricted": 2}[self.value]


class Action(str, Enum):
    PASSTHROUGH = "passthrough"  # send to external provider unchanged
    PSEUDONYMISE = "pseudonymise"  # pseudonymise, then send to external provider
    LOCAL = "local"  # keep inside the perimeter (self-hosted model)
    BLOCK = "block"  # refuse the request


class Upstream(BaseModel):
    base_url: str
    model: str
    api_key_env: str | None = None

    @property
    def api_key(self) -> str | None:
        return os.getenv(self.api_key_env) if self.api_key_env else None


class InjectionAction(str, Enum):
    FLAG = "flag"  # audit only
    STRIP_TOOLS = "strip_tools"  # remove tool definitions so a hijacked model cannot act
    BLOCK = "block"  # refuse the request


class InjectionPolicy(BaseModel):
    """Defence against indirect prompt injection.

    Routing a poisoned document to another model does not neutralise it, so the
    defence is layered instead: untrusted content is always *spotlighted*
    (wrapped in per-request random boundaries the model is told never to obey),
    and a positive detection removes the model's ability to act (tools) or
    blocks the request.
    """

    enabled: bool = True
    spotlight: bool = True
    on_detect: InjectionAction = InjectionAction.STRIP_TOOLS
    untrusted_roles: list[str] = Field(default_factory=lambda: ["tool"])
    untrusted_tags: list[str] = Field(
        default_factory=lambda: ["document", "context", "retrieved", "search_result"]
    )


class PseudonymScope(str, Enum):
    """Which population shares the same pseudonym for the same value.

    `global` lets the provider link a person across all customers of the
    gateway; `tenant` (default) limits linkage to one organisation; `session`
    prevents linkage across conversations at the cost of cross-session memory.
    """

    GLOBAL = "global"
    TENANT = "tenant"
    SESSION = "session"


class FailMode(str, Enum):
    CLOSED = "closed"  # detector failure -> request refused (default)
    OPEN = "open"  # detector failure -> request forwarded unprotected, audited


class NerConfig(BaseModel):
    backend: str = "none"  # none | gliner | presidio
    model: str | None = None
    threshold: float = 0.5
    languages: list[str] = Field(default_factory=lambda: ["en", "fr", "de"])


class VerifierConfig(BaseModel):
    """Detectors for a client that pseudonymises on its own side (e.g. privasoc).

    Such a client already replaces addresses with tokens drawn from fixed ranges. Any
    address outside those ranges is a value the client missed: it is reported as
    UNMAPPED_IP / UNMAPPED_MAC (set them `restricted` and `restricted: block` to refuse
    the request instead of pseudonymising it a second time).
    """

    require_address_manifest: bool = False
    unmapped_ip: bool = False
    ip_allow: list[str] = Field(
        default_factory=lambda: [
            "10.0.0.0/8",  # privasoc: private addresses
            "198.18.0.0/15",  # privasoc: public addresses
            "2001:db8::/32",  # privasoc: IPv6
            "127.0.0.0/8",
            "0.0.0.0/32",
            "224.0.0.0/4",
            "255.255.255.255/32",
            "::1/128",
            "::/128",
            "ff00::/8",
        ]
    )
    unmapped_mac: bool = False
    mac_allow_prefixes: list[str] = Field(default_factory=lambda: ["02"])


class Policy(BaseModel):
    upstreams: dict[str, Upstream]
    entities: dict[str, Sensitivity] = Field(default_factory=dict)
    actions: dict[Sensitivity, Action] = Field(
        default_factory=lambda: {
            Sensitivity.PUBLIC: Action.PASSTHROUGH,
            Sensitivity.CONFIDENTIAL: Action.PSEUDONYMISE,
            Sensitivity.RESTRICTED: Action.LOCAL,
        }
    )
    default_entity_sensitivity: Sensitivity = Sensitivity.CONFIDENTIAL
    injection: InjectionPolicy = Field(default_factory=InjectionPolicy)
    dictionary: dict[str, list[str]] = Field(default_factory=dict)
    pseudonym_scope: PseudonymScope = PseudonymScope.TENANT
    # System prompts are written by the application, not by users or documents.
    pseudonymise_system: bool = False
    fail_mode: FailMode = FailMode.CLOSED
    ner: NerConfig = Field(default_factory=NerConfig)
    # Built-in regex patterns to switch off (entity types, e.g. CREDIT_CARD on log data,
    # where millisecond timestamps pass the Luhn check).
    disabled_patterns: list[str] = Field(default_factory=list)
    # Regexes for values the client already pseudonymised: a detected span that lies
    # entirely inside a match is dropped (no double pseudonymisation).
    allowlist_patterns: list[str] = Field(default_factory=list)
    verifier: VerifierConfig = Field(default_factory=VerifierConfig)

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        with open(path, encoding="utf-8") as fh:
            return cls.model_validate(yaml.safe_load(fh))

    def sensitivity_of(self, entity_type: str) -> Sensitivity:
        return self.entities.get(entity_type, self.default_entity_sensitivity)


class Settings(BaseModel):
    ner_backend: str | None = Field(default_factory=lambda: os.getenv("SOVGATE_NER_BACKEND"))
    external_model: str | None = Field(default_factory=lambda: os.getenv("SOVGATE_EXTERNAL_MODEL"))
    policy_path: str = Field(default_factory=lambda: os.getenv("SOVGATE_POLICY", "config/policy.yaml"))
    hmac_secret: str = Field(default_factory=lambda: os.getenv("SOVGATE_HMAC_SECRET", ""))
    audit_path: str = Field(default_factory=lambda: os.getenv("SOVGATE_AUDIT_PATH", "audit/audit.jsonl"))
    vault_ttl_seconds: int = Field(default_factory=lambda: int(os.getenv("SOVGATE_VAULT_TTL", "3600")))
    # "key1:tenant-a,key2:tenant-b". When set, every /v1 call needs a bearer key and the
    # tenant is derived from it (a client can no longer choose its tenant by header).
    api_keys: dict[str, str] = Field(default_factory=lambda: _parse_keys(os.getenv("SOVGATE_API_KEYS", "")))


def _parse_keys(raw: str) -> dict[str, str]:
    keys: dict[str, str] = {}
    for item in raw.split(","):
        key, sep, tenant = item.strip().partition(":")
        if not item.strip():
            continue
        if not sep or not key or not tenant:
            raise ValueError("SOVGATE_API_KEYS must look like key:tenant[,key:tenant]")
        keys[key] = tenant
    return keys

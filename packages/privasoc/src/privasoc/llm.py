"""One client for every OpenAI-compatible server, local or remote (D12, D28, D36).

The client refuses to send a message that contains any original (un-pseudonymised) value:
the leak check is enforced here, at the only door to the outside, for every provider.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

import httpx

from privasoc.pseudo import Pseudonymizer

_THINK = re.compile(r"<think>.*?</think>", re.S)


class LeakError(RuntimeError):
    """An outgoing prompt still contains original values."""


class GatewayRefused(RuntimeError):
    """A sovgate egress gateway refused the call (privasoc+ PD8): blocked by policy (403),
    detector failure (503) or upstream unavailable (502). Nothing reached the provider."""

    def __init__(self, status: int, detail):
        self.status = status
        self.detail = detail
        reasons = detail.get("reasons") if isinstance(detail, dict) else None
        entities = detail.get("entities") if isinstance(detail, dict) else None
        msg = f"gateway refused the call (HTTP {status})"
        if reasons:
            msg += ": " + "; ".join(map(str, reasons))
        if entities:
            msg += f"; entity types found: {entities}"
        super().__init__(msg)


GATEWAY_HEADERS = ("action", "upstream", "request-id", "injection")


@dataclass(frozen=True)
class Endpoint:
    name: str  # "local" or "remote"
    url: str
    model: str
    api_key: str = ""
    think: bool = True  # False: ask reasoning models to answer directly (much faster)
    headers: tuple[tuple[str, str], ...] = ()  # e.g. X-Tenant-Id / X-Session-Id for sovgate

    @property
    def remote(self) -> bool:
        return self.name != "local"


@dataclass
class Reply:
    text: str
    latency_s: float
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    finish_reason: str | None = None  # "length" = truncated by max_tokens
    prompt_truncated: bool = False
    gateway: dict | None = None  # sovgate decision headers (no content), when one answered


class LLMClient:
    def __init__(
        self,
        endpoint: Endpoint,
        timeout: float = 300.0,
        call_log=None,
        max_tokens: int = 2048,
        num_ctx: int = 8192,
    ):
        if not endpoint.url or not endpoint.model:
            raise ValueError(f"{endpoint.name} LLM needs a URL and a model name")
        self.endpoint = endpoint
        self.timeout = timeout
        self.call_log = call_log  # callable(dict) -> None
        self.max_tokens = max_tokens  # a runaway generation must not block for minutes
        self.num_ctx = num_ctx  # context window requested from Ollama (fits 8 GB with 8B Q4)
        self.token_provider = None  # local vault callback; only minted address tokens
        self.native = False  # set by check() when the server is Ollama
        self.gateway: str | None = None  # sovgate version, set by check() when one answers

    def _headers(self) -> dict:
        key = self.endpoint.api_key
        headers = dict(self.endpoint.headers)
        if key:
            headers["Authorization"] = f"Bearer {key}"
        return headers

    def check(self) -> None:
        """Fail fast with a clear message if the server or the model is missing."""
        url = f"{self.endpoint.url.rstrip('/')}/models"
        try:
            r = httpx.get(url, headers=self._headers(), timeout=10)
            r.raise_for_status()
        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"{self.endpoint.name} LLM unreachable at {self.endpoint.url}: {exc}"
            ) from exc
        self.gateway = r.headers.get("x-sovgate-version")
        ids = {m.get("id") for m in r.json().get("data", [])}
        if not self.endpoint.remote:  # prefer Ollama's native API when it is there
            try:
                self.native = httpx.get(f"{self._base()}/api/tags", timeout=5).status_code == 200
            except httpx.HTTPError:
                self.native = False
        if ids and self.endpoint.model not in ids:
            raise RuntimeError(
                f"model {self.endpoint.model!r} not served; available: {sorted(ids)}"
            )

    def _openai(self, messages, json_mode, temperature):
        body = {
            "model": self.endpoint.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": self.max_tokens,
        }
        if self.gateway:
            text = "\n".join(m["content"] for m in messages)
            body["_privasoc_address_tokens"] = (
                self.token_provider(text) if self.token_provider else []
            )
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        if not self.endpoint.think and not self.endpoint.remote:
            body["reasoning_effort"] = "none"  # Ollama /v1: the only way to disable thinking
        url = f"{self.endpoint.url.rstrip('/')}/chat/completions"
        resp = httpx.post(url, json=body, headers=self._headers(), timeout=self.timeout)
        if resp.status_code == 400 and "reasoning_effort" in body:
            body.pop("reasoning_effort")  # a server that does not know the field
            resp = httpx.post(url, json=body, headers=self._headers(), timeout=self.timeout)
        is_gateway = "x-sovgate-version" in resp.headers
        if is_gateway and resp.status_code in (403, 502, 503):
            try:
                detail = resp.json().get("detail")
            except ValueError:
                detail = None
            raise GatewayRefused(resp.status_code, detail)
        resp.raise_for_status()
        data = resp.json()
        usage = data.get("usage") or {}
        choice = data["choices"][0]
        gateway = None
        if is_gateway:
            gateway = {
                h: resp.headers[f"x-sovgate-{h}"]
                for h in GATEWAY_HEADERS
                if f"x-sovgate-{h}" in resp.headers
            }
        return (
            choice["message"].get("content"),
            usage.get("prompt_tokens"),
            usage.get("completion_tokens"),
            choice.get("finish_reason"),
            gateway,
        )

    def _ollama(self, messages, json_mode, temperature):
        """Ollama's native API: the only one that accepts a context size per request
        (the OpenAI-compatible endpoint silently uses the server default, 4096 tokens)."""
        body = {
            "model": self.endpoint.model,
            "messages": messages,
            "stream": False,
            "think": self.endpoint.think,
            "options": {
                "temperature": temperature,
                "num_ctx": self.num_ctx,
                "num_predict": self.max_tokens,
            },
        }
        if json_mode:
            body["format"] = "json"
        resp = httpx.post(f"{self._base()}/api/chat", json=body, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        return (
            data["message"].get("content"),
            data.get("prompt_eval_count"),
            data.get("eval_count"),
            data.get("done_reason"),
            None,
        )

    def _base(self) -> str:
        url = self.endpoint.url.rstrip("/")
        return url[:-3] if url.endswith("/v1") else url

    def chat(
        self,
        messages: list[dict],
        *,
        originals: set[str],
        json_mode: bool = True,
        temperature: float = 0.2,
    ) -> Reply:
        if not self.endpoint.think and messages and messages[-1]["role"] == "user":
            # Qwen3-style soft switch; ignored by models without a reasoning mode.
            messages = [
                *messages[:-1],
                {**messages[-1], "content": messages[-1]["content"] + "\n/no_think"},
            ]
        outgoing = "\n".join(m["content"] for m in messages)
        leaks = Pseudonymizer.leaks(outgoing, originals)
        if leaks:
            raise LeakError(f"{len(leaks)} original value(s) in the prompt; refusing to send")
        t0 = time.monotonic()
        try:
            if self.native:
                text, pt, ct, finish, gateway = self._ollama(messages, json_mode, temperature)
            else:
                text, pt, ct, finish, gateway = self._openai(messages, json_mode, temperature)
        except GatewayRefused as exc:
            if self.call_log:  # sizes and the refusal only, never content
                self.call_log(
                    {
                        "provider": self.endpoint.name,
                        "model": self.endpoint.model,
                        "prompt_chars": len(outgoing),
                        "pseudonymised_values": len(originals),
                        "latency_s": round(time.monotonic() - t0, 3),
                        "api": "openai",
                        "gateway": {"refused": exc.status},
                    }
                )
            raise
        latency = time.monotonic() - t0
        reply = Reply(_THINK.sub("", text or "").strip(), latency, pt, ct, finish, gateway=gateway)
        # Ollama silently drops the start of a prompt longer than its context window.
        reply.prompt_truncated = bool(pt and self.native and pt >= self.num_ctx - 8)
        if self.call_log:
            self.call_log(
                {
                    "provider": self.endpoint.name,
                    "model": self.endpoint.model,
                    "prompt_chars": len(outgoing),
                    "pseudonymised_values": len(originals),
                    "latency_s": round(latency, 3),
                    "prompt_tokens": reply.prompt_tokens,
                    "completion_tokens": reply.completion_tokens,
                    "prompt_truncated": reply.prompt_truncated,
                    "api": "ollama" if self.native else "openai",
                    "gateway": reply.gateway,
                }
            )
        return reply

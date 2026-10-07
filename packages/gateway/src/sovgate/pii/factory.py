"""Build the detector chain from the policy."""

from __future__ import annotations

from ..config import Policy
from .detectors import DEFAULT_PATTERNS, Detector, DictionaryDetector, RegexDetector, UnmappedAddressDetector


def build_detectors(policy: Policy) -> list[Detector]:
    disabled = set(policy.disabled_patterns)
    unknown = disabled - {p.entity_type for p in DEFAULT_PATTERNS}
    if unknown:
        raise ValueError(f"unknown disabled_patterns: {sorted(unknown)}")
    patterns = [p for p in DEFAULT_PATTERNS if p.entity_type not in disabled]
    detectors: list[Detector] = [RegexDetector(patterns), DictionaryDetector(policy.dictionary)]
    v = policy.verifier
    if v.unmapped_ip or v.unmapped_mac:
        detectors.append(
            UnmappedAddressDetector(
                ip=v.unmapped_ip,
                mac=v.unmapped_mac,
                ip_allow=v.ip_allow,
                mac_allow_prefixes=v.mac_allow_prefixes,
            )
        )
    backend = policy.ner.backend.lower()
    if backend == "gliner":
        from .ner import GlinerDetector

        kwargs = {"threshold": policy.ner.threshold}
        if policy.ner.model:
            kwargs["model"] = policy.ner.model
        detectors.append(GlinerDetector(**kwargs))
    elif backend == "presidio":
        from .ner import PresidioDetector

        detectors.append(PresidioDetector(tuple(policy.ner.languages), policy.ner.threshold))
    elif backend != "none":
        raise ValueError(f"unknown NER backend: {policy.ner.backend}")
    return detectors

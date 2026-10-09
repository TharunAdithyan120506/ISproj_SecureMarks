"""Loads and validates config/policies.yaml.

An unknown cipher or a missing field raises at start-up, so the server never runs
with a half-understood policy. Each protected route declares a minimum policy;
a session opened under a weaker one is refused with 403 policy_too_weak.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

KEY_LEN_BY_CIPHER = {"AES-128-GCM": 16, "AES-256-GCM": 32}


class RateLimit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capacity: int = Field(gt=0)
    refill_per_sec: float = Field(gt=0)


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = ""
    cipher: Literal["AES-128-GCM", "AES-256-GCM"]
    key_exchange: Literal["X25519", "RSA-OAEP-2048"]
    kdf: Literal["HKDF-SHA256"] | None = None
    key_len: int | None = None
    signature: Literal["Ed25519", "RSA-PSS-2048", "none"]
    max_payload_kb: int = Field(gt=0)
    rate_limit: RateLimit
    replay_window_s: int = Field(gt=0)
    audit: Literal["full", "decisions"]

    @model_validator(mode="after")
    def _check(self) -> "Policy":
        expected = KEY_LEN_BY_CIPHER[self.cipher]
        if self.key_len is None:
            self.key_len = expected
        elif self.key_len != expected:
            raise ValueError(f"key_len {self.key_len} does not match {self.cipher}")
        if self.key_exchange == "X25519" and self.kdf is None:
            raise ValueError("X25519 policies must name a kdf")
        return self

    @property
    def strength(self) -> int:
        """Ordering used for `policy_too_weak`: AES-256 sessions outrank AES-128."""
        return 2 if self.key_len == 32 else 1

    @property
    def max_payload_bytes(self) -> int:
        return self.max_payload_kb * 1024


class PolicySet:
    def __init__(self, policies: dict[str, Policy], raw: dict):
        self.policies = policies
        self.raw = raw

    def get(self, name: str | None) -> Policy | None:
        return self.policies.get(name or "")

    def __contains__(self, name: str) -> bool:
        return name in self.policies

    def names(self) -> list[str]:
        return list(self.policies)

    def satisfies(self, session_policy: str, minimum: str) -> bool:
        return self.policies[session_policy].strength >= self.policies[minimum].strength


def load_policies(path: Path) -> PolicySet:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict) or not raw:
        raise ValueError(f"{path} defines no policies")
    policies = {name: Policy(name=name, **body) for name, body in raw.items()}
    for required in ("confidential", "normal"):
        if required not in policies:
            raise ValueError(f"{path} must define the '{required}' policy")
    return PolicySet(policies, raw)

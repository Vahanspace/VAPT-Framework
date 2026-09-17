"""Scope enforcement — the first guardrail.

Nothing in this framework is allowed to touch a target that is not explicitly listed in a
scope allowlist. The ScopeGuard is consulted before every active network action. It:

  * matches hosts against an explicit allowlist (exact host or a single leading ``*.`` wildcard),
  * enforces an optional port allowlist,
  * honours an exclude list that always wins over the allowlist,
  * refuses any target whose environment is flagged as production, and
  * refuses obvious production hostnames unless ``allow_production`` is explicitly true.

A ScopeViolation is raised for anything not affirmatively permitted (default-deny).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit


class ScopeViolation(Exception):
    """Raised when an action targets something outside the authorized scope."""


_PROD_MARKERS = ("prod", "production", "www.", "live.")


@dataclass
class Scope:
    name: str
    environment: str = "staging"            # staging | test | dev | local | production
    allowed_hosts: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=list)   # empty => any port
    excluded_hosts: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)  # URL path prefixes never touched
    source_roots: list[str] = field(default_factory=list)    # local paths for static analysis
    allow_production: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "Scope":
        return cls(
            name=data.get("name", "unnamed"),
            environment=str(data.get("environment", "staging")).lower(),
            allowed_hosts=[h.lower() for h in data.get("allowed_hosts", [])],
            allowed_ports=[int(p) for p in data.get("allowed_ports", [])],
            excluded_hosts=[h.lower() for h in data.get("excluded_hosts", [])],
            excluded_paths=list(data.get("excluded_paths", [])),
            source_roots=list(data.get("source_roots", [])),
            allow_production=bool(data.get("allow_production", False)),
        )


class ScopeGuard:
    def __init__(self, scope: Scope) -> None:
        self.scope = scope

    # -- host matching -------------------------------------------------------
    @staticmethod
    def _host_matches(host: str, pattern: str) -> bool:
        host = host.lower()
        pattern = pattern.lower()
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".example.com"
            return host.endswith(suffix) and host != suffix[1:]
        return host == pattern

    def host_in_scope(self, host: str) -> bool:
        if not host:
            return False
        host = host.lower()
        if any(self._host_matches(host, p) for p in self.scope.excluded_hosts):
            return False
        return any(self._host_matches(host, p) for p in self.scope.allowed_hosts)

    # -- production safety ----------------------------------------------------
    def _is_production_like(self, host: str) -> bool:
        if self.scope.environment == "production":
            return True
        return any(marker in host.lower() for marker in _PROD_MARKERS)

    # -- the enforced check ---------------------------------------------------
    def assert_in_scope(self, url: str) -> None:
        parts = urlsplit(url if "//" in url else "//" + url)
        host = parts.hostname or ""
        port = parts.port

        if not self.host_in_scope(host):
            raise ScopeViolation(f"host not in allowlist: {host!r} (url={url})")

        if self.scope.allowed_ports and port is not None and port not in self.scope.allowed_ports:
            raise ScopeViolation(f"port not allowed: {port} for {host!r}")

        path = parts.path or "/"
        for excluded in self.scope.excluded_paths:
            if path.startswith(excluded):
                raise ScopeViolation(f"path excluded from testing: {path!r}")

        if self._is_production_like(host) and not self.scope.allow_production:
            raise ScopeViolation(
                f"refusing production-like target {host!r}; set allow_production=true "
                "only with explicit written authorization for production testing"
            )

    def is_in_scope(self, url: str) -> bool:
        try:
            self.assert_in_scope(url)
            return True
        except ScopeViolation:
            return False

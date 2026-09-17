"""Scanner contract.

Every scanner declares its blast radius up front so the engine can enforce guardrails
uniformly:

  * ``category`` = PASSIVE  -> reads local source/config or already-captured responses.
                              Needs a scope (for any file roots) but no active authorization.
  * ``category`` = ACTIVE   -> sends network traffic to the target. Requires a valid
                              authorization with active testing enabled, and every URL is
                              scope-checked and rate-limited.
  * ``destructive`` = True  -> may change or destroy data / degrade availability. Requires
                              authorization with destructive testing enabled.

The engine (core/engine.py) is the only place that decides to run a scanner; scanners never
bypass their own gates.
"""
from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ..core.findings import Finding


class Category(Enum):
    PASSIVE = "passive"
    ACTIVE = "active"


@dataclass
class ScanContext:
    """Everything a scanner is allowed to use, handed to it by the engine."""
    scope: "object"                       # vaptframework.core.scope.ScopeGuard
    authorization: "object"               # vaptframework.core.authorization.Authorization
    throttle: Optional["object"] = None   # vaptframework.core.ratelimit.Throttle
    targets: list[str] = field(default_factory=list)   # in-scope base URLs
    source_roots: list[str] = field(default_factory=list)
    evidence_dir: str = "evidence"
    options: dict = field(default_factory=dict)
    credentials: dict = field(default_factory=dict)     # {"userA": {...}, "userB": {...}}


@dataclass
class ScanResult:
    scanner: str
    ran: bool
    reason: str = ""                       # why it was skipped, if ran is False
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class Scanner(ABC):
    name: str = "scanner"
    category: Category = Category.PASSIVE
    destructive: bool = False
    required_tool: Optional[str] = None    # external binary this scanner shells out to, if any

    @abstractmethod
    def scan(self, ctx: ScanContext) -> list[Finding]:
        """Perform the scan and return findings. Called only after the engine's gates pass."""
        raise NotImplementedError

    # -- helpers -------------------------------------------------------------
    def tool_available(self) -> bool:
        if not self.required_tool:
            return True
        return shutil.which(self.required_tool) is not None

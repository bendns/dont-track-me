"""Base module contract — every tracking vector implements this interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import StrEnum
from importlib.util import find_spec
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class ThreatLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    """A single audit finding — one specific privacy issue detected."""

    title: str
    description: str
    threat_level: ThreatLevel
    remediation: str


class AuditResult(BaseModel):
    """Result of running a module's audit."""

    module_name: str
    score: int = Field(ge=0, le=100)  # 0 = fully exposed, 100 = fully protected
    findings: list[Finding] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class ProtectionResult(BaseModel):
    """Result of running a module's protect action."""

    module_name: str
    dry_run: bool
    actions_taken: list[str] = Field(default_factory=list)
    actions_available: list[str] = Field(default_factory=list)


class BaseModule(ABC):
    """Abstract base class for all tracking-vector modules.

    Every module must implement audit(), protect(), and get_educational_content().
    """

    name: str
    display_name: str
    description: str

    @abstractmethod
    async def audit(self, **kwargs: Any) -> AuditResult:
        """Run a non-destructive scan and return findings with a score."""
        ...

    @abstractmethod
    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        """Apply countermeasures. Dry-run by default — never modifies without --apply."""
        ...

    @abstractmethod
    def get_educational_content(self) -> str:
        """Return markdown explaining the threat, how it works, and why VPN doesn't help."""
        ...

    def get_dependencies(self) -> list[str]:
        """Return list of optional pip package names this module needs."""
        return []

    def is_available(self) -> bool:
        """Check whether all required optional dependencies are installed."""
        for dep in self.get_dependencies():
            # Normalize package name for import (e.g. "Pillow" -> "PIL", "dnspython" -> "dns")
            import_name = {
                "Pillow": "PIL",
                "dnspython": "dns",
                "pypdf": "pypdf",
            }.get(dep, dep)
            if find_spec(import_name) is None:
                return False
        return True

    def _load_info_md(self) -> str:
        """Load the info.md file co-located with the module."""
        module_dir = Path(__file__).parent  # overridden by subclass file location
        # Subclasses live in modules/<name>/module.py, info.md is next to it
        info_path = Path(self.__class__.__module__.replace(".", "/")).parent / "info.md"
        # Resolve relative to src root
        src_root = Path(__file__).resolve().parent.parent
        abs_path = src_root / info_path
        if abs_path.exists():
            return abs_path.read_text()
        return f"No educational content available for {self.display_name}."

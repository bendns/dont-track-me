"""Base module contract — every tracking vector implements this interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import StrEnum
from importlib.util import find_spec
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from dont_track_me.core.checklist import PrivacyCheck

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

    def get_educational_content(self) -> str:
        """Return markdown explaining the threat, how it works, and why VPN doesn't help."""
        return self._load_info_md()

    def get_checklist(self) -> list[PrivacyCheck] | None:
        """Return privacy checks for interactive checklist modules, or None."""
        return None

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
        """Load educational content from shared/content/<name>.md."""
        from dont_track_me.core.paths import SHARED_DIR

        info_path = SHARED_DIR / "content" / f"{self.name}.md"
        if info_path.exists():
            return info_path.read_text()
        return f"No educational content available for {self.display_name}."

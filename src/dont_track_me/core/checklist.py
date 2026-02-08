"""Privacy checklist infrastructure — interactive self-assessment for platforms without API access."""

from __future__ import annotations

from pydantic import BaseModel

from dont_track_me.core.base import Finding, ProtectionResult, ThreatLevel

# Score penalty per threat level when a check is unsafe
THREAT_WEIGHTS: dict[ThreatLevel, int] = {
    ThreatLevel.CRITICAL: 15,
    ThreatLevel.HIGH: 10,
    ThreatLevel.MEDIUM: 6,
    ThreatLevel.LOW: 3,
    ThreatLevel.INFO: 0,
}


class PrivacyCheck(BaseModel):
    """A single yes/no privacy setting check."""

    id: str
    question: str
    description: str
    threat_level: ThreatLevel
    remediation: str
    category: str  # "visibility", "data_sharing", "security"
    safe_answer: bool = True


def compute_checklist_score(
    checks: list[PrivacyCheck],
    responses: dict[str, bool],
) -> tuple[int, list[Finding]]:
    """Score a checklist based on user responses.

    Unanswered questions are assumed unsafe.
    Returns (score 0-100, list of findings).
    """
    score = 100
    findings: list[Finding] = []

    for check in checks:
        answer = responses.get(check.id)
        is_safe = answer == check.safe_answer if answer is not None else False

        if is_safe:
            findings.append(
                Finding(
                    title=f"OK: {check.question}",
                    description=check.description,
                    threat_level=ThreatLevel.INFO,
                    remediation="No action needed.",
                )
            )
        else:
            penalty = THREAT_WEIGHTS.get(check.threat_level, 5)
            score -= penalty
            findings.append(
                Finding(
                    title=check.question,
                    description=check.description,
                    threat_level=check.threat_level,
                    remediation=check.remediation,
                )
            )

    return max(0, min(100, score)), findings


async def protect_checklist_module(
    module_name: str,
    display_name: str,
    checks: list[PrivacyCheck],
    responses: dict[str, bool] | None = None,
) -> ProtectionResult:
    """Generate a privacy hardening guide for a checklist-based module.

    With *responses*: return only remediation steps for unsafe settings.
    Without: return the full hardening guide for all checks.
    """
    actions: list[str] = []

    if responses:
        for check in checks:
            answer = responses.get(check.id)
            is_safe = answer == check.safe_answer if answer is not None else False
            if not is_safe:
                actions.append(
                    f"[{check.threat_level.value.upper()}] {check.remediation}"
                )
    else:
        actions.append(f"--- {display_name} Privacy Hardening Guide ---")
        for check in checks:
            actions.append(f"[{check.threat_level.value.upper()}] {check.question}")
            actions.append(f"  {check.remediation}")

    if not actions:
        actions.append(f"All {display_name} privacy settings are properly configured.")

    return ProtectionResult(
        module_name=module_name,
        dry_run=True,  # Always dry-run — cannot apply via API
        actions_available=actions,
    )

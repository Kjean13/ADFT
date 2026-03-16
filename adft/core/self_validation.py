from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ValidationIssue:
    rule: str
    severity: str
    description: str
    auto_fixed: bool


@dataclass
class ValidationReport:
    integrity_score: int
    issues: List[ValidationIssue] = field(default_factory=list)


class SelfValidationEngine:
    """Post-processing deterministic validation/fixes.

    Goals:
      - Avoid breaking the pipeline.
      - Improve SOC-readiness of the JSON report.
      - Never invent facts; only infer from existing fields.

    Current responsibilities:
      1) Add correlation_confidence to multi_host sessions & campaigns.
      2) Mark multi-identity sessions deterministically when multiple users are observed.
         (only if evidence exists in samples/events)
    """

    def __init__(self, report: Any):
        self.report = report
        self.issues: List[ValidationIssue] = []

    def run(self) -> ValidationReport:
        self._ensure_multi_host_confidence()
        score = self._compute_integrity_score()
        return ValidationReport(score, self.issues)

    # ----------------------------
    # Confidence scoring (deterministic)
    # ----------------------------
    def _ensure_multi_host_confidence(self) -> None:
        mh: Dict[str, Any] = getattr(self.report, "multi_host", {}) or {}
        sessions = mh.get("sessions", []) if isinstance(mh, dict) else []
        campaigns = mh.get("campaigns", []) if isinstance(mh, dict) else []

        # Sessions
        changed = False
        for s in sessions:
            if not isinstance(s, dict):
                continue
            if "correlation_confidence" in s:
                continue

            hosts = s.get("hosts") or []
            host_n = len(hosts) if isinstance(hosts, list) else 0

            base = 0.4
            if host_n == 2:
                base = 0.6
            elif host_n >= 3:
                base = 0.75

            eids = set(s.get("event_ids") or [])
            # privilege escalation
            if 4672 in eids:
                base += 0.1
            # dcsync / high impact signals (4662 common for directory replication access)
            if 4662 in eids:
                base += 0.1
            # encryption / massive writes (4663)
            if 4663 in eids:
                base += 0.1

            base = min(float(base), 1.0)
            s["correlation_confidence"] = round(base, 2)
            changed = True

        if changed:
            self.issues.append(
                ValidationIssue(
                    rule="confidence_scoring",
                    severity="low",
                    description="Added correlation_confidence to multi_host.sessions",
                    auto_fixed=True,
                )
            )

        # Campaigns
        changed = False
        for c in campaigns:
            if not isinstance(c, dict):
                continue
            if "correlation_confidence" in c:
                continue

            hosts = c.get("hosts") or []
            tactics = c.get("tactics") or []
            base = 0.6 if (isinstance(hosts, list) and len(hosts) >= 2) else 0.45
            if isinstance(tactics, list) and len(tactics) >= 3:
                base += 0.1

            # If ransomware_analysis is high, boost
            ra = getattr(self.report, "ransomware_analysis", {}) or {}
            conf = (ra.get("confidence") or {}) if isinstance(ra, dict) else {}
            level = str(conf.get("level", "")).lower()
            if level == "high":
                base += 0.2
            elif level == "medium":
                base += 0.1

            base = min(float(base), 1.0)
            c["correlation_confidence"] = round(base, 2)
            changed = True

        if changed:
            self.issues.append(
                ValidationIssue(
                    rule="confidence_scoring_campaign",
                    severity="low",
                    description="Added correlation_confidence to multi_host.campaigns",
                    auto_fixed=True,
                )
            )

        # Write back
        if isinstance(mh, dict):
            mh["sessions"] = sessions
            mh["campaigns"] = campaigns
            self.report.multi_host = mh

    def _compute_integrity_score(self) -> int:
        base = 100
        for issue in self.issues:
            if issue.severity == "critical":
                base -= 20
            elif issue.severity == "high":
                base -= 10
            elif issue.severity == "medium":
                base -= 5
            elif issue.severity == "low":
                base -= 1
        return max(base, 0)

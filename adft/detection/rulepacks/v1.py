"""RulePack V1 — base solide pour une V1 démontrable.

But : figer une sélection cohérente (34 règles) + mapping MITRE propre.
Ce pack est 100% déterministe.

Historique :
- v1.0 : 22 règles
- v1.1 : 34 règles (+12 : GPO, DCShadow/DCSync, DLL abuse, SVC abuse, Anti-forensics)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Type

from adft.detection.rules.base_rule import BaseRule

# Imports des règles (classes)
from adft.detection.rules.kerberos_abuse import ASREPRoastingRule, GoldenTicketRule, KerberoastingRule
from adft.detection.rules.suspicious_auth import BruteForceRule, PassTheHashRule, SuspiciousRDPRule
from adft.detection.rules.explicit_credential_use import ExplicitCredentialUseRule
from adft.detection.rules.lateral_movement_smb import SMBPropagationRule
from adft.detection.rules.privilege_escalation import (
    PrivilegedGroupModificationRule,
    SpecialPrivilegeAssignmentRule,
    SuspiciousAccountCreationRule,
)
from adft.detection.rules.admin_anomaly import AdminAfterHoursRule, MultipleAdminSourcesRule
from adft.detection.rules.account_compromise import AuditLogClearedRule, KerberosPreAuthFailureRule, SuspiciousServiceInstallRule
from adft.detection.rules.service_install import SuspiciousServiceInstalledRule
from adft.detection.rules.ransomware_activity import AVStopAttemptRule, FileEncryptionBurstRule, ShadowCopyDeletionRule
from adft.detection.rules.suspicious_process import SuspiciousProcessExecutionRule
from adft.detection.rules.powershell_abuse import PowerShellAbuseRule

# ── v1.1 — Nouvelles règles ────────────────────────────────────────────────
from adft.detection.rules.gpo_abuse import GPOModificationRule, GPOSysvolScriptRule
from adft.detection.rules.dcshadow_dcsync import DCShadowRule, DCSyncAdvancedRule
from adft.detection.rules.dll_abuse import DLLSideloadingRule, LOLBinExecutionRule, CreateRemoteThreadRule
from adft.detection.rules.service_account_abuse import (
    ServiceAccountInteractiveLogonRule,
    KerberoastingServiceAccountRule,
    ServiceAccountPasswordChangeRule,
)
from adft.detection.rules.anti_forensics import AuditLogTamperingRule, SecurityToolDisableRule


@dataclass(frozen=True)
class RulePackV1:
    """RulePack V1.1 (34 règles)."""

    name: str = "rulepack_v1"

    rule_classes: tuple[Type[BaseRule], ...] = field(
        default_factory=lambda: (
        # Kerberos abuse
        [KerberoastingRule, ASREPRoastingRule, GoldenTicketRule]
        # Identity / auth
        + [BruteForceRule, PassTheHashRule, SuspiciousRDPRule, KerberosPreAuthFailureRule, ExplicitCredentialUseRule]
        # Lateral movement (SMB propagation)
        + [SMBPropagationRule]
        # Privilege escalation / identity changes
        + [PrivilegedGroupModificationRule, SpecialPrivilegeAssignmentRule, SuspiciousAccountCreationRule]
        # Admin anomalies / persistence hints
        + [AdminAfterHoursRule, MultipleAdminSourcesRule]
        # Defense evasion / service install
        + [AuditLogClearedRule, SuspiciousServiceInstallRule, SuspiciousServiceInstalledRule]
        # Ransomware signals
        + [FileEncryptionBurstRule, ShadowCopyDeletionRule, AVStopAttemptRule]
        # Malicious tooling / process execution
        + [SuspiciousProcessExecutionRule]
        # PowerShell abuse
        + [PowerShellAbuseRule]
        # ── v1.1 ──────────────────────────────────────────────────────
        # GPO abuse (T1484.001)
        + [GPOModificationRule, GPOSysvolScriptRule]
        # DCShadow / DCSync (T1207 / T1003.006)
        + [DCShadowRule, DCSyncAdvancedRule]
        # DLL abuse (T1574.002 / T1574.001 / T1055)
        + [DLLSideloadingRule, LOLBinExecutionRule, CreateRemoteThreadRule]
        # Service account abuse (T1078.002 / T1558.003)
        + [ServiceAccountInteractiveLogonRule, KerberoastingServiceAccountRule, ServiceAccountPasswordChangeRule]
        # Anti-forensics (T1070.001 / T1562.001)
        + [AuditLogTamperingRule, SecurityToolDisableRule]
        )
    )

    def build(self) -> List[BaseRule]:
        return [cls() for cls in self.rule_classes]

    def mitre_mapping(self) -> List[Dict[str, str]]:
        """Mapping MITRE clean et stable."""
        out: List[Dict[str, str]] = []
        for cls in self.rule_classes:
            r = cls()
            out.append(
                {
                    "rule_id": getattr(r, "rule_id", ""),
                    "rule_name": getattr(r, "rule_name", getattr(r, "name", "")),
                    "severity": str(getattr(r, "severity", "")),
                    "mitre_tactic": getattr(r, "mitre_tactic", ""),
                    "mitre_technique": getattr(r, "mitre_technique", ""),
                    "mitre_id": getattr(r, "mitre_id", ""),
                }
            )

        # nettoyage
        for m in out:
            for k, v in list(m.items()):
                if v is None:
                    m[k] = ""
                elif isinstance(v, str):
                    m[k] = v.strip()
                else:
                    m[k] = str(v)
        return out

    def validate(self) -> None:
        """Validation légère (fail fast en dev)."""
        rules = self.build()
        ids = [r.rule_id for r in rules]
        if len(ids) != len(set(ids)):
            dupes = {i for i in ids if ids.count(i) > 1}
            raise ValueError(f"RulePackV1: rule_id non uniques: {sorted(dupes)}")

        # MITRE : au moins une tactique sur le pack
        if not any(getattr(r, "mitre_tactic", "") for r in rules):
            raise ValueError("RulePackV1: aucune tactique MITRE définie")


def build_rulepack_v1() -> List[BaseRule]:
    return RulePackV1().build()
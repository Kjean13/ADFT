"""ADFT — Générateur de scripts PowerShell candidats pour le hardening."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional

from adft.core.models import HardeningFinding, HardeningReport


class PowerShellScriptGenerator:
    SCRIPT_HEADER = """#═══════════════════════════════════════════════════════════════
# ADFT — Script PowerShell candidat de remédiation
#
# ⚠️  AVERTISSEMENT
#   - Ce script est un candidat généré par ADFT.
#   - Vérifier, adapter et tester avant exécution.
#   - Exécuter d'abord en pré-production quand c'est possible.
#
# Finding        : {finding_id} — {title}
# Priorité       : {priority}
# Périmètre      : {scope}
# Confiance      : {confidence}
# Catégorie      : {category}
#═══════════════════════════════════════════════════════════════

#Requires -Modules ActiveDirectory
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

"""

    SCRIPT_TEMPLATES: Dict[str, str] = {
        "HARD-001": """
Write-Host "[ADFT] Inventaire des comptes de service avec SPN" -ForegroundColor Cyan
$svcAccounts = Get-ADUser -LDAPFilter "(servicePrincipalName=*)" -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes,PasswordLastSet,Enabled |
  Where-Object { $_.Enabled -eq $true } |
  Select-Object SamAccountName,ServicePrincipalName,msDS-SupportedEncryptionTypes,PasswordLastSet
$svcAccounts | Format-Table -AutoSize

Write-Host "`n[ADFT] Comptes sans AES uniquement" -ForegroundColor Yellow
$weakEnc = $svcAccounts | Where-Object { -not $_.msDS-SupportedEncryptionTypes -or (($_.msDS-SupportedEncryptionTypes -band 24) -eq 0) }
$weakEnc | Format-Table -AutoSize

# --- CANDIDAT DE CORRECTION (décommenter après validation) ---
# foreach ($acct in $weakEnc) {
#   Set-ADUser -Identity $acct.SamAccountName -KerberosEncryptionType AES128,AES256
# }
# Envisager la migration vers gMSA si le service le permet.
""",
        "HARD-002": """
Write-Host "[ADFT] Recherche des comptes sans pré-authentification Kerberos" -ForegroundColor Cyan
$noPreAuth = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth,Enabled |
  Where-Object { $_.Enabled -eq $true }
$noPreAuth | Select-Object SamAccountName,Enabled | Format-Table -AutoSize

# --- CANDIDAT DE CORRECTION ---
# foreach ($acct in $noPreAuth) {
#   Set-ADAccountControl -Identity $acct.SamAccountName -DoesNotRequirePreAuth $false
# }
""",
        "HARD-003": """
Write-Host "[ADFT] Vérification du compte KRBTGT" -ForegroundColor Cyan
$krbtgt = Get-ADUser -Identity 'krbtgt' -Properties PasswordLastSet
$krbtgt | Select-Object SamAccountName,PasswordLastSet | Format-Table -AutoSize
Write-Host "[ADFT] Préparer une double rotation KRBTGT selon procédure de crise" -ForegroundColor Yellow
# AUCUNE rotation automatique ici.
# Documenter la séquence, l'intervalle et la validation de réplication avant exécution manuelle.
""",
        "HARD-010": """
Write-Host "[ADFT] Export des groupes privilégiés" -ForegroundColor Cyan
$groups = 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','Print Operators'
foreach ($g in $groups) {
  try {
    Get-ADGroupMember -Identity $g -Recursive | Select-Object @{N='Group';E={$g}},Name,SamAccountName,ObjectClass
  } catch {
    Write-Warning "Impossible de lire le groupe $g : $_"
  }
}
# Export conseillé : ... | Export-Csv .\\privileged_groups_snapshot.csv -NoTypeInformation
""",
        "HARD-011": """
param([string[]]$Identity = @())
Write-Host "[ADFT] Contrôle ciblé des identités à risque" -ForegroundColor Cyan
if (-not $Identity -or $Identity.Count -eq 0) {
  Write-Warning "Passez les identités à contrôler avec -Identity user1,user2"
}
foreach ($id in $Identity) {
  Get-ADUser -Identity $id -Properties LastLogonDate,Enabled,PasswordLastSet,MemberOf |
    Select-Object SamAccountName,Enabled,LastLogonDate,PasswordLastSet,MemberOf | Format-List
}
# Réinitialisation éventuelle à mener séparément après qualification IR.
""",
        "HARD-012": """
Write-Host "[ADFT] Revue des comptes créés récemment" -ForegroundColor Cyan
Get-ADUser -Filter * -Properties whenCreated,Enabled,MemberOf |
  Where-Object { $_.whenCreated -gt (Get-Date).AddDays(-14) } |
  Select-Object SamAccountName,whenCreated,Enabled,MemberOf | Sort-Object whenCreated -Descending | Format-Table -AutoSize
""",
        "HARD-020": """
Write-Host "[ADFT] Politique de mot de passe / verrouillage" -ForegroundColor Cyan
$policy = Get-ADDefaultDomainPasswordPolicy
$policy | Select-Object LockoutThreshold,LockoutDuration,LockoutObservationWindow,MinPasswordLength,ComplexityEnabled | Format-List
# Ajuster les seuils via GPO ou policy de domaine après validation CAB.
""",
        "HARD-030": """
Write-Host "[ADFT] Contrôle de la surface d'administration latérale" -ForegroundColor Cyan
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol | Format-List
Get-Service WinRM | Select-Object Status,StartType | Format-Table -AutoSize
Write-Host "[ADFT] Contrôler aussi les ACL de pare-feu et les jump hosts autorisés." -ForegroundColor Yellow
""",
        "HARD-031": """
Write-Host "[ADFT] Inventaire rapide RDP" -ForegroundColor Cyan
Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections | Format-List
Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue |
  Select-Object DisplayName,Enabled,Profile,Direction,Action | Format-Table -AutoSize
# Restreindre ensuite les sources et imposer NLA/MFA selon le design d'administration.
""",
        "HARD-032": """
param([string]$ServiceName = '')
Write-Host "[ADFT] Revue des services créés récemment" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, ProviderName, Message | Format-List
if ($ServiceName) {
  Get-Service -Name $ServiceName -ErrorAction SilentlyContinue | Format-List *
}
# Stop-Service / sc.exe delete à exécuter séparément après validation du binaire et du propriétaire.
""",
        "HARD-040": """
Write-Host "[ADFT] Vérification de l'audit avancé" -ForegroundColor Cyan
AuditPol /get /category:*
Write-Host "`n[ADFT] Vérifier la remontée SIEM des événements 4624,4625,4648,4672,4768,4769,4771,4776,5136" -ForegroundColor Yellow
""",
        "HARD-041": """
Write-Host "[ADFT] Checklist d'audit AD post-incident" -ForegroundColor Cyan
@(
  'Tiering administratif',
  'Groupes privilégiés',
  'Comptes inactifs / obsolètes',
  'Délégations',
  'GPO sensibles',
  'Comptes de service et SPN',
  'Journalisation DC'
) | ForEach-Object { " - $_" }
""",
        "HARD-042": """
Write-Host "[ADFT] Contrôle de la résilience des journaux" -ForegroundColor Cyan
wevtutil gl Security
wevtutil gl System
wevtutil gl Application
Write-Host "[ADFT] Vérifier aussi la centralisation distante et les permissions de nettoyage des journaux." -ForegroundColor Yellow
""",
    }

    def enrich_findings(self, report: HardeningReport) -> None:
        for finding in report.findings:
            script = self._generate_script(finding)
            if script:
                finding.powershell_fix = script

    def _metadata_block(self, finding: HardeningFinding) -> str:
        lines = []
        if finding.evidence:
            lines.append('# Preuves observées')
            for item in finding.evidence[:5]:
                lines.append(f'# - {item}')
        if finding.prerequisites:
            lines.append('#')
            lines.append('# Prérequis')
            for item in finding.prerequisites[:5]:
                lines.append(f'# - {item}')
        if finding.validation_steps:
            lines.append('#')
            lines.append('# Vérifications post-action')
            for item in finding.validation_steps[:5]:
                lines.append(f'# - {item}')
        if finding.rollback_steps:
            lines.append('#')
            lines.append('# Rollback / garde-fous')
            for item in finding.rollback_steps[:5]:
                lines.append(f'# - {item}')
        if finding.analyst_notes:
            lines.append('#')
            lines.append(f'# Note analyste: {finding.analyst_notes}')
        return '\n'.join(lines).rstrip() + '\n\n' if lines else ''

    def _generate_script(self, finding: HardeningFinding) -> Optional[str]:
        template = self.SCRIPT_TEMPLATES.get(finding.finding_id)
        if not template:
            return None
        header = self.SCRIPT_HEADER.format(
            finding_id=finding.finding_id,
            title=finding.title,
            priority=finding.priority.upper(),
            scope=finding.candidate_scope,
            confidence=finding.confidence,
            category=finding.category,
        )
        return header + self._metadata_block(finding) + template.lstrip('\n')

    def export_scripts(self, report: HardeningReport, output_dir: str) -> None:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        manifest = {
            'summary': report.summary,
            'coverage': report.script_coverage,
            'scripts': [],
        }
        exported = 0
        for finding in report.sorted_by_priority():
            if not finding.powershell_fix:
                continue
            filename = f"{finding.finding_id}_remediation.ps1"
            filepath = output_path / filename
            filepath.write_text(finding.powershell_fix, encoding='utf-8')
            manifest['scripts'].append({
                'finding_id': finding.finding_id,
                'title': finding.title,
                'priority': finding.priority,
                'confidence': finding.confidence,
                'path': filename,
                'validation_steps': finding.validation_steps,
            })
            exported += 1
            print(f"  [Script] ✓ {filepath}")

        (output_path / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
        print(f"\n  {exported} script(s) PowerShell exporté(s) dans {output_dir}")


ScriptGenerator = PowerShellScriptGenerator

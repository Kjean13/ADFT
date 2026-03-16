
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Optional

from adft.core.models.events import NormalizedEvent, Severity
from adft.core.quality import QualityCollector

EVENT_ACTIONS: dict[int, str] = {
    4624: "Connexion réussie",
    4625: "Connexion échouée",
    4648: "Connexion avec identifiants explicites",
    4672: "Privilèges spéciaux assignés à un nouveau logon",
    4720: "Compte utilisateur créé",
    4722: "Compte utilisateur activé",
    4723: "Tentative de changement de mot de passe",
    4724: "Réinitialisation de mot de passe",
    4725: "Compte utilisateur désactivé",
    4726: "Compte utilisateur supprimé",
    4728: "Membre ajouté à un groupe global de sécurité",
    4732: "Membre ajouté à un groupe local de sécurité",
    4756: "Membre ajouté à un groupe universel de sécurité",
    4768: "Demande de ticket Kerberos TGT (AS-REQ)",
    4769: "Demande de ticket Kerberos TGS (TGS-REQ)",
    4771: "Pré-authentification Kerberos échouée",
    4776: "Tentative de validation NTLM",
    4662: "Opération effectuée sur un objet AD",
    4688: "Nouveau processus créé",
    4697: "Service installé sur le système",
    1102: "Journal d'audit effacé",
}

EVENT_SEVERITY: dict[int, Severity] = {
    4624: Severity.INFO,
    4625: Severity.LOW,
    4648: Severity.MEDIUM,
    4672: Severity.MEDIUM,
    4720: Severity.MEDIUM,
    4728: Severity.HIGH,
    4732: Severity.HIGH,
    4756: Severity.HIGH,
    4768: Severity.INFO,
    4769: Severity.INFO,
    4771: Severity.LOW,
    4776: Severity.INFO,
    4662: Severity.MEDIUM,
    4688: Severity.INFO,
    4697: Severity.HIGH,
    1102: Severity.CRITICAL,
}

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")


class EventNormalizer:
    SCHEMA_VERSION = "normalized-event-v1"

    def __init__(self) -> None:
        self._normalized_count = 0
        self._error_count = 0
        self._dropped_count = 0
        self._quality = QualityCollector("normalization")

    def normalize_all(self, raw_events: list[dict[str, Any]]) -> list[NormalizedEvent]:
        normalized: list[NormalizedEvent] = []
        for index, raw in enumerate(raw_events):
            try:
                event = self.normalize_one(raw, event_index=index)
                if event is not None:
                    normalized.append(event)
                    self._normalized_count += 1
                else:
                    self._dropped_count += 1
            except Exception as exc:
                self._error_count += 1
                self._quality.error(
                    "normalization_failed",
                    "Un événement brut n'a pas pu être normalisé.",
                    event_index=index,
                    error=str(exc),
                )
        return normalized

    def normalize_one(self, raw: dict[str, Any], event_index: int | None = None) -> Optional[NormalizedEvent]:
        if not isinstance(raw, dict):
            self._quality.warn(
                "raw_event_not_object",
                "Événement brut ignoré car il n'est pas un objet JSON/dict.",
                event_index=event_index,
                observed_type=type(raw).__name__,
            )
            return None

        event_id = self._extract_event_id(raw, event_index=event_index)
        if event_id is None:
            self._quality.warn(
                "event_id_missing_or_invalid",
                "Événement ignoré car EventID est absent ou invalide.",
                event_index=event_index,
                available_keys=sorted(list(raw.keys()))[:15],
            )
            return None

        timestamp = self._extract_timestamp(raw, event_index=event_index)
        user = self._extract_field(raw, [
            "TargetUserName", "user.name", "username", "user", "User", "SubjectUserName",
            "TargetUser", "Account_Name", "AccountName", "UserName", "account", "Account",
            "winlog.user.name",
        ])

        source_host = self._extract_field(raw, [
            "WorkstationName", "Workstation", "ClientName", "ClientComputerName",
            "source.hostname", "src_host", "source_host", "hostname", "host", "Host",
            "host.name", "host.hostname",
            "winlog.event_data.WorkstationName", "winlog.event_data.Workstation",
            "winlog.event_data.ClientName", "winlog.event_data.ClientComputerName",
            "winlog.event_data.SourceWorkstation", "winlog.computer_name",
            "winlog.computerName", "Computer", "ComputerName", "computer", "machine",
            "System.Computer", "Event.System.Computer",
        ])
        target_host = self._extract_field(raw, [
            "System.Computer", "Event.System.Computer", "Computer", "ComputerName",
            "winlog.computer_name", "winlog.computerName", "host.name", "dest_host",
            "target_host", "TargetServerName", "destination.hostname", "hostname", "host",
            "computer", "machine",
        ])

        if not source_host and target_host:
            source_host = target_host
        if not target_host and source_host:
            target_host = source_host

        workstation = self._extract_field(raw, [
            "WorkstationName", "Workstation", "ClientName", "ClientComputerName",
            "winlog.event_data.WorkstationName", "winlog.event_data.Workstation",
            "winlog.event_data.ClientName", "winlog.event_data.ClientComputerName",
            "winlog.event_data.SourceWorkstation", "client.domain", "client.hostname",
        ])
        if event_id in (4624, 4625, 4648, 4768, 4769, 4771, 4776) and workstation:
            source_host = workstation.strip()

        domain = self._extract_field(raw, [
            "TargetDomainName", "SubjectDomainName", "user.domain", "domain", "winlog.user.domain",
        ])
        ip_address = self._extract_ip(raw, [
            "IpAddress", "IpAddr", "ClientAddress", "ClientIP", "RemoteAddress",
            "SourceNetworkAddress", "source.ip", "client.ip", "network.forwarded_ip",
            "src_ip", "winlog.event_data.IpAddress", "winlog.event_data.IpAddr",
            "winlog.event_data.ClientAddress", "winlog.event_data.ClientIP",
            "winlog.event_data.RemoteAddress", "winlog.event_data.SourceNetworkAddress",
        ])

        logon_type = self._extract_int(raw, ["LogonType", "logon.type", "logon_type", "winlog.event_data.LogonType"])
        ticket_encryption = self._extract_field(raw, ["TicketEncryptionType", "ticket.encryption_type", "EncryptionType", "winlog.event_data.TicketEncryptionType"])
        ticket_options = self._extract_field(raw, ["TicketOptions", "ticket.options", "winlog.event_data.TicketOptions"])
        service_name = self._extract_field(raw, ["ServiceName", "service.name", "ServicePrincipalName", "winlog.event_data.ServiceName"])
        target_user = self._extract_field(raw, ["MemberName", "MemberSid", "member.name", "TargetUserName", "winlog.event_data.MemberName", "winlog.event_data.MemberSid"])
        group_name = self._extract_field(raw, ["TargetUserName", "group.name", "GroupName", "winlog.event_data.TargetUserName", "winlog.event_data.GroupName"])

        if event_id in (4728, 4732, 4756):
            group_name = self._extract_field(raw, ["TargetUserName", "group.name", "winlog.event_data.TargetUserName"])
            user = self._extract_field(raw, ["SubjectUserName", "user.name", "winlog.event_data.SubjectUserName", "winlog.user.name"])

        process_name = self._extract_field(raw, ["NewProcessName", "process.name", "ProcessName", "process.executable", "winlog.event_data.NewProcessName"])
        status = self._extract_field(raw, ["Status", "event.outcome", "status", "winlog.event_data.Status"])
        sub_status = self._extract_field(raw, ["SubStatus", "sub_status", "winlog.event_data.SubStatus"])

        action = EVENT_ACTIONS.get(event_id, f"Événement Windows {event_id}")
        severity = EVENT_SEVERITY.get(event_id, Severity.INFO)
        source_log = raw.get("_source_file", "unknown")

        return NormalizedEvent(
            timestamp=timestamp,
            event_id=event_id,
            user=user,
            source_host=source_host,
            target_host=target_host,
            action=action,
            severity=severity,
            raw_event=raw,
            source_log=source_log,
            domain=domain,
            logon_type=logon_type,
            ticket_encryption=ticket_encryption,
            ticket_options=ticket_options,
            service_name=service_name,
            target_user=target_user,
            group_name=group_name,
            process_name=process_name,
            ip_address=ip_address,
            status=status,
            sub_status=sub_status,
        )

    def _extract_event_id(self, raw: dict[str, Any], event_index: int | None = None) -> Optional[int]:
        for key in ("EventID", "event_id", "event.code", "eventid"):
            value = raw.get(key)
            if value is None:
                continue
            try:
                return int(value)
            except (ValueError, TypeError):
                self._quality.warn(
                    "event_id_type_coercion_failed",
                    "EventID non convertible en entier.",
                    event_index=event_index,
                    key=key,
                    value=str(value),
                )

        event_obj = raw.get("event", {})
        if isinstance(event_obj, dict):
            code = event_obj.get("code")
            if code is not None:
                try:
                    return int(code)
                except (ValueError, TypeError):
                    self._quality.warn("event_code_invalid", "event.code non convertible en entier.", event_index=event_index, value=str(code))

        winlog_obj = raw.get("winlog", {})
        if isinstance(winlog_obj, dict):
            ev = winlog_obj.get("event_id")
            if ev is not None:
                try:
                    return int(ev)
                except (ValueError, TypeError):
                    self._quality.warn("winlog_event_id_invalid", "winlog.event_id non convertible en entier.", event_index=event_index, value=str(ev))
        return None

    def _extract_timestamp(self, raw: dict[str, Any], event_index: int | None = None) -> datetime:
        for key in ("TimeCreated", "@timestamp", "timestamp", "event.created", "datetime"):
            value = raw.get(key)
            if isinstance(value, (int, float)):
                try:
                    self._quality.warn("timestamp_epoch_coerced", "Timestamp epoch converti en ISO UTC.", event_index=event_index, key=key)
                    return datetime.fromtimestamp(float(value), tz=timezone.utc)
                except Exception:
                    continue
            if value and isinstance(value, str):
                try:
                    clean = value.replace("Z", "+00:00").rstrip()
                    return datetime.fromisoformat(clean)
                except ValueError:
                    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
                        try:
                            self._quality.warn("timestamp_format_coerced", "Timestamp converti depuis un format non ISO.", event_index=event_index, key=key)
                            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
                        except ValueError:
                            continue
                    self._quality.warn("timestamp_invalid", "Timestamp invalide, valeur minimale utilisée.", event_index=event_index, key=key, value=value)
        self._quality.warn("timestamp_missing", "Timestamp absent, valeur minimale utilisée.", event_index=event_index)
        return datetime.min.replace(tzinfo=timezone.utc)

    @staticmethod
    def _extract_field(raw: dict[str, Any], candidates: list[str]) -> str:
        for key in candidates:
            if "." in key:
                parts = key.split(".")
                value: Any = raw
                for part in parts:
                    if isinstance(value, dict):
                        value = value.get(part)
                    else:
                        value = None
                        break
                if isinstance(value, str) and value.strip():
                    return value.strip()
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and item.strip():
                            return item.strip()
            else:
                value = raw.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and item.strip():
                            return item.strip()
        return ""

    @staticmethod
    def _extract_int(raw: dict[str, Any], candidates: list[str]) -> Optional[int]:
        for key in candidates:
            value = raw.get(key)
            if value is None and "." in key:
                parts = key.split(".")
                value2: Any = raw
                for part in parts:
                    if isinstance(value2, dict):
                        value2 = value2.get(part)
                    else:
                        value2 = None
                        break
                value = value2
            if value is not None:
                try:
                    return int(value)
                except (ValueError, TypeError):
                    continue
        return None

    @staticmethod
    def _is_noise_ip(ip: str) -> bool:
        ip = (ip or "").strip()
        if not ip or ip in ("-", "0.0.0.0", "::"):
            return True
        try:
            obj = ipaddress.ip_address(ip)
            return bool(
                obj.is_multicast
                or obj.is_loopback
                or obj.is_unspecified
                or obj.is_link_local
            )
        except ValueError:
            return True

    @classmethod
    def _extract_ip(cls, raw: dict[str, Any], candidates: list[str]) -> str:
        def pick_ip_from_any(v: Any) -> str:
            if isinstance(v, str):
                s = v.strip()
                if not s:
                    return ""
                m4 = _IPV4_RE.search(s)
                if m4:
                    ip = m4.group(0)
                    return "" if cls._is_noise_ip(ip) else ip
                m6 = _IPV6_RE.search(s)
                if m6:
                    ip = m6.group(0)
                    return "" if cls._is_noise_ip(ip) else ip
                return ""
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        m4 = _IPV4_RE.search(item)
                        if m4:
                            ip = m4.group(0)
                            if not cls._is_noise_ip(ip):
                                return ip
                for item in v:
                    if isinstance(item, str):
                        m6 = _IPV6_RE.search(item)
                        if m6:
                            ip = m6.group(0)
                            if not cls._is_noise_ip(ip):
                                return ip
            return ""

        for key in candidates:
            value: Any = None
            if "." in key:
                parts = key.split(".")
                value = raw
                for part in parts:
                    if isinstance(value, dict):
                        value = value.get(part)
                    else:
                        value = None
                        break
            else:
                value = raw.get(key)
            ip = pick_ip_from_any(value)
            if ip:
                return ip
        return ""

    @property
    def stats(self) -> dict[str, int]:
        data = {
            "normalized": self._normalized_count,
            "errors": self._error_count,
            "dropped": self._dropped_count,
        }
        data.update(self._quality.snapshot().get("stats", {}))
        return data

    @property
    def quality_report(self) -> dict[str, Any]:
        snap = self._quality.snapshot()
        snap["schema_version"] = self.SCHEMA_VERSION
        snap["stats"] = {**self.stats, **(snap.get("stats") or {})}
        return snap

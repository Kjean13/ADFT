
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class QualityIssue:
    module: str
    code: str
    message: str
    severity: str = "warning"
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "code": self.code,
            "message": self.message,
            "severity": self.severity,
            "context": dict(self.context),
        }


class QualityCollector:
    """Collecte légère des erreurs et avertissements data-quality."""

    def __init__(self, module: str, issue_limit: int = 50) -> None:
        self.module = module
        self.issue_limit = issue_limit
        self._stats: Counter[str] = Counter()
        self._issues: List[QualityIssue] = []

    def incr(self, key: str, amount: int = 1) -> None:
        self._stats[key] += int(amount)

    def warn(self, code: str, message: str, **context: Any) -> None:
        self._record("warning", code, message, context)

    def error(self, code: str, message: str, **context: Any) -> None:
        self._record("error", code, message, context)

    def _record(self, severity: str, code: str, message: str, context: Dict[str, Any]) -> None:
        self._stats[f"{severity}s"] += 1
        if len(self._issues) >= self.issue_limit:
            self._stats["issues_dropped"] += 1
            return
        self._issues.append(QualityIssue(self.module, code, message, severity, context))

    def extend(self, other: "QualityCollector | dict[str, Any] | None") -> None:
        if other is None:
            return
        data = other.snapshot() if isinstance(other, QualityCollector) else dict(other)
        for key, value in (data.get("stats", {}) or {}).items():
            try:
                self._stats[key] += int(value)
            except Exception:
                continue
        for issue in data.get("issues", []) or []:
            if len(self._issues) >= self.issue_limit:
                self._stats["issues_dropped"] += 1
                break
            if isinstance(issue, dict):
                self._issues.append(QualityIssue(
                    module=str(issue.get("module") or self.module),
                    code=str(issue.get("code") or "unknown"),
                    message=str(issue.get("message") or ""),
                    severity=str(issue.get("severity") or "warning"),
                    context=dict(issue.get("context") or {}),
                ))

    def snapshot(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "stats": dict(self._stats),
            "issues": [i.to_dict() for i in self._issues],
        }


from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class BaseParser(ABC):
    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        ...

    @abstractmethod
    def parse(self, file_path: Path) -> list[dict[str, Any]]:
        ...

    @property
    @abstractmethod
    def parser_name(self) -> str:
        ...

    @property
    def quality_report(self) -> dict[str, Any]:
        return {"module": self.parser_name, "stats": {}, "issues": []}

    def pop_quality_report(self) -> dict[str, Any]:
        return self.quality_report

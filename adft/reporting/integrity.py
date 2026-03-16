
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_integrity_manifest(output_dir: str | Path, files: Iterable[str | Path]) -> Path:
    base = Path(output_dir)
    entries = []
    for file in files:
        path = Path(file)
        if not path.is_absolute():
            path = base / path
        if not path.exists() or not path.is_file():
            continue
        entries.append({
            "path": path.name,
            "size_bytes": path.stat().st_size,
            "sha256": file_sha256(path),
        })
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "sha256",
        "files": sorted(entries, key=lambda x: x["path"]),
    }
    out = base / "adft_integrity.json"
    out.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return out

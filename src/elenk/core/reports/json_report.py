"""JSON report: the most complete, machine-readable view of the
result. Meant for scripting an automated accept/reject decision, or
feeding the data into other tooling."""

from __future__ import annotations

import json
from pathlib import Path

from elenk.core.models import ScanResult


def to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent, ensure_ascii=False)


def write_json_report(result: ScanResult, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(to_json(result), encoding="utf-8")
    return output_path

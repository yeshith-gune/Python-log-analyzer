import json
import csv
import io
from datetime import datetime
from models import AttackRecord
SEVERITY_COLOR = {
    "low":      "\033[33m",   # yellow
    "medium":   "\033[33;1m",  # bold yellow
    "high":     "\033[31m",   # red
    "critical": "\033[31;1m",  # bold red
}
RESET = "\033[0m"


def _fmt_dt(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "—"


def report_terminal(attacks: list[AttackRecord]) -> None:
    if not attacks:
        print("✓  No brute-force activity detected.")
        return

    print(f"\n{'─'*64}")

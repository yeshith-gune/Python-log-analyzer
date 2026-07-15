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
    print(f"  BRUTE FORCE REPORT  —  {len(attacks)} source(s) flagged")
    print(f"{'─'*64}\n")

    for a in attacks:
        color = SEVERITY_COLOR.get(a.severity, "")
        duration = (
            a.last_seen - a.first_seen).seconds // 60 if a.first_seen else 0
        top_users = ", ".join(list(a.distinct_users)[:5])
        if len(a.distinct_users) > 5:
            top_users += f" (+{len(a.distinct_users)-5} more)"

        print(f"  {color}[{a.severity.upper():8s}]{RESET}  {a.source_ip}")
        print(f"             Failures : {a.failed_count}")
        print(f"          Burst rate  : {a.burst_score} failures/min")
        print(
            f"        Distinct users: {len(a.distinct_users)}  ({top_users})")
        print(
            f"          Time range  : {_fmt_dt(a.first_seen)} → {_fmt_dt(a.last_seen)}  ({duration} min)")
        print()


def report_json(attacks: list[AttackRecord]) -> str:
    def record_to_dict(a: AttackRecord) -> dict:
        return {
            "ip": a.source_ip,
            "severity": a.severity,
            "failed_count": a.failed_count,
            "burst_score": a.burst_score,
            "distinct_users": sorted(a.distinct_users),
            "first_seen": _fmt_dt(a.first_seen),
            "last_seen": _fmt_dt(a.last_seen),
        }
    return json.dumps([record_to_dict(a) for a in attacks], indent=2)


def report_csv(attacks: list[AttackRecord]) -> str:
    buf = io.StringIO()
    fields = ["ip", "severity", "failed_count", "burst_score",
              "distinct_users", "first_seen", "last_seen"]
    writer = csv.DictWriter(buf, fieldnames=fields)
    writer.writeheader()
    for a in attacks:
        writer.writerow({
            "ip": a.source_ip,
            "severity": a.severity,
            "failed_count": a.failed_count,
            "burst_score": a.burst_score,
            "distinct_users": len(a.distinct_users),
            "first_seen": _fmt_dt(a.first_seen),
            "last_seen": _fmt_dt(a.last_seen),
        }
    return json.dumps([record_to_dict(a) for a in attacks], indent=2)

def report_csv(attacks: list[AttackRecord]) -> str:
    buf=io.StringIO()
        fields=["ip", "severity", "failed_count", "burst_score",
              "distinct_users", "first_seen", "last_seen"]
    writer=csv.DictWriter(buf, fieldnames=fields)

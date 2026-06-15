from collections import defaultdict
from datetime import timedelta
from models import LogEntry, AttackRecord


def aggregate(entries: list[LogEntry], window_minutes: int = 10) -> dict[str, AttackRecord]:
    """
    Build a per-IP failure profile.
    window_minutes: size of the sliding window for burst-rate calculation.
    """
    records: dict[str, AttackRecord] = {}
    # Bucket failures by IP
    ip_failures: dict[str, list[LogEntry]] = defaultdict(list)
    for entry in entries:
        if entry.event in ("failed", "invalid_user") and entry.source_ip:
            ip_failures[entry.source_ip].append(entry)

    window = timedelta(minutes=window_minutes)

    for ip, failures in ip_failures.items():
        failures.sort(key=lambda e: e.timestamp)
        usernames = [f.username for f in failures if f.username]
# Sliding window for peak burst rate
        peak_rate = 0.0
        for i, failure in enumerate(failures):
            window_end = failure.timestamp + window

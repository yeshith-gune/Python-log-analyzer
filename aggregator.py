from collections import defaultdict
from datetime import timedelta
from models import LogEntry, AttackRecord
def aggregate(entries: list[LogEntry], window_minutes: int = 10) -> dict[str, AttackRecord]:
    """
    Build a per-IP failure profile.
    window_minutes: size of the sliding window for burst-rate calculation.
    """
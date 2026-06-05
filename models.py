from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class LogEntry:
    timestamp: datetime
    hostname: str
    service: str
    pid: int | None
    event: str          # "failed", "accepted", "invalid_user", "disconnect"
    username: str | None
    source_ip: str | None
    port: int | None

@dataclass
class AttackRecord:
    source_ip: str
    failed_count: int
    distinct_users: set = field(default_factory=set)
    first_seen: datetime = None
    last_seen: datetime = None
    burst_score: float = 0.0    # failures per minute at peak
    usernames_tried: list = field(default_factory=list)
    severity: str = "low"       # low / medium / high / critical
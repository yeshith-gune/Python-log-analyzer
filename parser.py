import re
from datetime import datetime
from models import LogEntry
# Syslog header: "Jan  3 14:22:01 hostname sshd[1234]:"
SYSLOG_RE = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'   # timestamp
    r'(\S+)\s+'                                        # hostname
    r'(\w+)(?:\[(\d+)\])?:\s+'                        # service[pid]
    r'(.+)$'                                           # message body
)
# Patterns for message bodies we care about
PATTERNS = {
    "failed": re.compile(
        r'Failed (?:password|publickey) for (?:invalid user )?(\S+) '
        r'from ([\d.]+) port (\d+)'
    ),
    "invalid_user": re.compile(
        r'Invalid user (\S+) from ([\d.]+)(?:\s+port (\d+))?'
    ),
    "accepted": re.compile(
        r'Accepted (?:password|publickey) for (\S+) '
        r'from ([\d.]+) port (\d+)'
    ),
    "disconnect": re.compile(
        r'Disconnected from(?: invalid user)? (\S+) ([\d.]+) port (\d+)'
    ),
    "pam_failed": re.compile(
        r'pam_unix\(\w+:\w+\): authentication failure;.*?user=(\S+)'
    ),
}


def parse_line(line: str, year: int = None) -> LogEntry | None:
    year = year or datetime.now().year
    m = SYSLOG_RE.match(line.strip())
    if not m:
        return None
    ts_str, hostname, service, pid, body = m.groups()
    try:
        timestamp = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    for event_type, pattern in PATTERNS.items():
        em = pattern.search(body)
        if em:
            groups = em.groups()
            username = groups[0] if groups else None
            source_ip = groups[1] if len(groups) > 1 else None
            port = int(groups[2]) if len(groups) > 2 and groups[2] else None
            return LogEntry(
                timestamp=timestamp,
                hostname=hostname,
                service=service,
                pid=int(pid) if pid else None,
                event=event_type,
                username=username,
                source_ip=source_ip,
                port=port,
            )
    return None


def parse_file(path: str) -> list[LogEntry]:
    entries = []
    year = datetime.now().year

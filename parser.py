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

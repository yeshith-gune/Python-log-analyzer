from models import AttackRecord
# Thresholds — adjust to your baseline
THRESHOLDS = {
    "min_failures_low":    5,    # flag at all
    "min_failures_medium": 20,   # escalate
    "min_failures_high":   50,   # likely automated scanner
    "burst_rate_medium":   2.0,  # failures/min to call medium
    "burst_rate_high":     5.0,  # failures/min to call high
    "distinct_users_low":  3,    # credential stuffing starts here
    "distinct_users_high": 10,   # definite user enumeration
}


def score_record(record: AttackRecord) -> AttackRecord:
    T = THRESHOLDS
    severity = "low"

    # Rule 1: total failure count
    if record.failed_count >= T["min_failures_high"]:
        severity = "high"
    elif record.failed_count >= T["min_failures_medium"]:
        severity = "medium"
    elif record.failed_count < T["min_failures_low"]:
        severity = "low"

    # Rule 2: escalate on burst rate
    if record.burst_score >= T["burst_rate_high"]:
        severity = max_severity(severity, "high")
    elif record.burst_score >= T["burst_rate_medium"]:
        severity = max_severity(severity, "medium")

    # Rule 3: credential stuffing (many distinct users)
    if len(record.distinct_users) >= T["distinct_users_high"]:
        severity = "critical"       # override — strong signal
    elif len(record.distinct_users) >= T["distinct_users_low"]:
        severity = max_severity(severity, "medium")

    record.severity = severity
    return record


def _severity_rank(s: str) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}[s]

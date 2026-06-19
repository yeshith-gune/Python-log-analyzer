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
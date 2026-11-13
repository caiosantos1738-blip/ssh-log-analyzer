
"""Risk scoring engine for SSH security alerts."""

from datetime import datetime, timedelta


# Base scores assigned to each detection rule.
RULE_BASE_SCORES = {
    "SSH_BRUTE_FORCE": 50,
    "SSH_PASSWORD_SPRAYING": 55,
    "SSH_FAILURES_FOLLOWED_BY_SUCCESS": 65,
}

# Minimum event count expected for each detection rule.
RULE_MIN_EVENTS = {
    "SSH_BRUTE_FORCE": 5,
    "SSH_PASSWORD_SPRAYING": 5,
    "SSH_FAILURES_FOLLOWED_BY_SUCCESS": 4,
}

# Scoring configuration.
EVENT_VOLUME_BONUS = 5
MAX_VOLUME_BONUS = 20
CORRELATION_BONUS = 15
CORRELATION_WINDOW = timedelta(minutes=10)

RISK_LEVELS = (
    (24, "LOW"),
    (49, "MEDIUM"),
    (74, "HIGH"),
    (100, "CRITICAL"),
)


def classify_risk(score):
    """Convert a numeric risk score into a risk classification."""

    score = max(0, min(100, score))

    for maximum, level in RISK_LEVELS:
        if score <= maximum:
            return level

    return "CRITICAL"


def score_alert(alert, correlated=False):
    """Calculate the risk score for an individual alert."""

    rule_id = alert["rule_id"]

    if rule_id not in RULE_BASE_SCORES:
        raise ValueError(f"Unknown detection rule: {rule_id}")

    base_score = RULE_BASE_SCORES[rule_id]
    minimum_events = RULE_MIN_EVENTS[rule_id]

    event_count = alert["event_count"]

    additional_events = max(
        0, event_count - minimum_events
    )

    volume_bonus = min(
        additional_events * EVENT_VOLUME_BONUS,
        MAX_VOLUME_BONUS
    )

    correlation_bonus = (
        CORRELATION_BONUS if correlated else 0
    )

    return min(
        100,
        base_score + volume_bonus + correlation_bonus
    )


def parse_alert_timestamp(value):
    """Convert an ISO timestamp string into a datetime object."""

    if isinstance(value, datetime):
        return value

    return datetime.fromisoformat(value)


def alerts_are_temporally_correlated(alert_a, alert_b):
    """Check whether two alert intervals overlap or are within 10 minutes."""

    start_a = parse_alert_timestamp(alert_a["first_seen"])
    end_a = parse_alert_timestamp(alert_a["last_seen"])

    start_b = parse_alert_timestamp(alert_b["first_seen"])
    end_b = parse_alert_timestamp(alert_b["last_seen"])

    # Alert intervals overlap.
    if start_a <= end_b and start_b <= end_a:
        return True

    # Calculate the gap between non-overlapping intervals.
    if end_a < start_b:
        time_gap = start_b - end_a
    else:
        time_gap = start_a - end_b

    return time_gap <= CORRELATION_WINDOW


def enrich_alerts(alerts):
    """Add risk scores and classifications to security alerts."""

    correlated_alerts = set()

    # Compare alerts from the same IP but different detection rules.
    for index, alert_a in enumerate(alerts):
        for other_index, alert_b in enumerate(alerts):
            if index == other_index:
                continue

            if alert_a["source_ip"] != alert_b["source_ip"]:
                continue

            if alert_a["rule_id"] == alert_b["rule_id"]:
                continue

            if alerts_are_temporally_correlated(
                alert_a, alert_b
            ):
                correlated_alerts.add(index)
                break

    enriched_alerts = []

    for index, alert in enumerate(alerts):
        correlated = index in correlated_alerts

        risk_score = score_alert(
            alert,
            correlated=correlated
        )

        risk_level = classify_risk(risk_score)

        enriched_alert = alert.copy()
        enriched_alert["risk_score"] = risk_score
        enriched_alert["risk_level"] = risk_level
        enriched_alert["severity"] = risk_level

        enriched_alerts.append(enriched_alert)

    return enriched_alerts

import csv
import json
from pathlib import Path

from src.parser import parse_file
from src.detection import run_detections
from src.risk import enrich_alerts


# Configuration
INPUT_FILE = Path("evidence/ssh-auth.log")
OUTPUT_CSV = Path("reports/ssh-analysis.csv")
OUTPUT_JSON = Path("reports/security-alerts.json")


def anonymize(value, mapping, prefix):
    """Generate consistent pseudonyms for sensitive values."""
    if value not in mapping:
        mapping[value] = f"{prefix}_{len(mapping) + 1:03d}"
    return mapping[value]


def serialize_timestamp(value):
    """Convert datetime objects to ISO strings."""
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value) if value is not None else None


def analyze():
    if not INPUT_FILE.exists():
        print(f"[ERROR] Input file not found: {INPUT_FILE}")
        return

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)

    # Parse raw log events
    events = parse_file(INPUT_FILE)

    if not events:
        print("[INFO] No SSH authentication events found.")
        return

    # Run detection rules and calculate risk scores
    alerts = run_detections(events)
    alerts = enrich_alerts(alerts)

    # Get the highest risk score for each source IP
    risk_by_ip = {}

    for alert in alerts:
        source_ip = alert["source_ip"]

        if (
            source_ip not in risk_by_ip
            or alert["risk_score"] > risk_by_ip[source_ip]["risk_score"]
        ):
            risk_by_ip[source_ip] = {
                "risk_score": alert["risk_score"],
                "risk_level": alert["risk_level"]
            }

    # Anonymization mappings
    username_map = {}
    ip_map = {}

    # Export sanitized events to CSV
    fields = [
        "timestamp",
        "event",
        "username",
        "source_ip",
        "severity",
        "risk_score",
        "risk_level"
    ]

    with OUTPUT_CSV.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        for event in events:
            original_ip = event["source_ip"]
            original_username = event["username"]

            safe_ip = anonymize(original_ip, ip_map, "IP")
            safe_username = anonymize(
                original_username, username_map, "USER"
            )

            risk = risk_by_ip.get(original_ip)

            if risk:
                severity = risk["risk_level"]
                risk_score = risk["risk_score"]
                risk_level = risk["risk_level"]
            else:
                severity = "INFO"
                risk_score = 0
                risk_level = "LOW"

            writer.writerow({
                "timestamp": serialize_timestamp(
                    event["timestamp"]
                ),
                "event": event["event"],
                "username": safe_username,
                "source_ip": safe_ip,
                "severity": severity,
                "risk_score": risk_score,
                "risk_level": risk_level
            })

    # Create sanitized JSON alerts
    safe_alerts = []

    for alert in alerts:
        safe_alerts.append({
            "rule_id": alert["rule_id"],
            "severity": alert["severity"],
            "risk_score": alert["risk_score"],
            "risk_level": alert["risk_level"],
            "description": alert["description"],
            "source_ip": anonymize(
                alert["source_ip"], ip_map, "IP"
            ),
            "event_count": alert["event_count"],
            "first_seen": serialize_timestamp(
                alert["first_seen"]
            ),
            "last_seen": serialize_timestamp(
                alert["last_seen"]
            ),
            "mitre_technique_id": alert["mitre_technique_id"],
            "mitre_technique_name": alert["mitre_technique_name"],
            "mitre_tactic": alert["mitre_tactic"]
        })

    with OUTPUT_JSON.open("w", encoding="utf-8") as file:
        json.dump(
            safe_alerts,
            file,
            indent=4,
            ensure_ascii=False
        )

    # Statistics
    failed_count = sum(
        event["event"] == "FAILED_LOGIN"
        for event in events
    )

    successful_count = sum(
        event["event"] == "SUCCESSFUL_LOGIN"
        for event in events
    )

    print("\n===== ADVANCED SECURITY LOG ANALYZER =====")
    print(f"Events analyzed: {len(events)}")
    print(f"Failed logins: {failed_count}")
    print(f"Successful logins: {successful_count}")
    print(f"Security alerts: {len(alerts)}")
    print(f"Usernames anonymized: {len(username_map)}")
    print(f"IPs anonymized: {len(ip_map)}")
    print(f"\nCSV report: {OUTPUT_CSV}")
    print(f"JSON alerts: {OUTPUT_JSON}")
    print("[OK] Risk scoring completed.")
    print("[OK] Exported data has been anonymized.")


if __name__ == "__main__":
    analyze()

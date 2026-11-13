
import unittest

from src.risk import (
    classify_risk,
    score_alert,
    enrich_alerts,
)


class RiskScoringTests(unittest.TestCase):

    def create_alert(
        self,
        rule_id="SSH_BRUTE_FORCE",
        event_count=5,
        source_ip="192.0.2.10",
        first_seen="2026-11-06T10:00:00+00:00",
        last_seen="2026-11-06T10:04:00+00:00"
    ):
        return {
            "rule_id": rule_id,
            "severity": "HIGH",
            "description": "Test alert",
            "source_ip": source_ip,
            "event_count": event_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "mitre_technique_id": "T1110.001",
            "mitre_technique_name": "Password Guessing",
            "mitre_tactic": "Credential Access",
        }

    def test_risk_classification_boundaries(self):
        self.assertEqual(classify_risk(0), "LOW")
        self.assertEqual(classify_risk(24), "LOW")
        self.assertEqual(classify_risk(25), "MEDIUM")
        self.assertEqual(classify_risk(49), "MEDIUM")
        self.assertEqual(classify_risk(50), "HIGH")
        self.assertEqual(classify_risk(74), "HIGH")
        self.assertEqual(classify_risk(75), "CRITICAL")
        self.assertEqual(classify_risk(100), "CRITICAL")

    def test_brute_force_base_score(self):
        alert = self.create_alert()
        self.assertEqual(score_alert(alert), 50)

    def test_event_volume_bonus(self):
        alert = self.create_alert(event_count=7)
        self.assertEqual(score_alert(alert), 60)

    def test_event_volume_bonus_is_capped(self):
        alert = self.create_alert(event_count=20)
        self.assertEqual(score_alert(alert), 70)

    def test_correlation_bonus(self):
        alert = self.create_alert()
        self.assertEqual(score_alert(alert, correlated=True), 65)

    def test_unknown_rule_is_rejected(self):
        alert = self.create_alert(rule_id="UNKNOWN_RULE")

        with self.assertRaises(ValueError):
            score_alert(alert)

    def test_alert_enrichment(self):
        alert = self.create_alert()
        enriched = enrich_alerts([alert])

        self.assertEqual(len(enriched), 1)
        self.assertEqual(enriched[0]["risk_score"], 50)
        self.assertEqual(enriched[0]["risk_level"], "HIGH")
        self.assertEqual(enriched[0]["severity"], "HIGH")
        self.assertNotIn("risk_score", alert)

    def test_correlation_between_rules(self):
        alerts = [
            self.create_alert(rule_id="SSH_BRUTE_FORCE"),
            self.create_alert(rule_id="SSH_PASSWORD_SPRAYING"),
        ]

        enriched = enrich_alerts(alerts)

        self.assertEqual(enriched[0]["risk_score"], 65)
        self.assertEqual(enriched[1]["risk_score"], 70)

    def test_different_ips_are_not_correlated(self):
        alerts = [
            self.create_alert(
                rule_id="SSH_BRUTE_FORCE",
                source_ip="192.0.2.10"
            ),
            self.create_alert(
                rule_id="SSH_PASSWORD_SPRAYING",
                source_ip="192.0.2.20"
            ),
        ]

        enriched = enrich_alerts(alerts)

        self.assertEqual(enriched[0]["risk_score"], 50)
        self.assertEqual(enriched[1]["risk_score"], 55)

    def test_correlation_within_time_window(self):
        alerts = [
            self.create_alert(
                rule_id="SSH_BRUTE_FORCE",
                first_seen="2026-11-06T10:00:00+00:00",
                last_seen="2026-11-06T10:04:00+00:00"
            ),
            self.create_alert(
                rule_id="SSH_PASSWORD_SPRAYING",
                first_seen="2026-11-06T10:07:00+00:00",
                last_seen="2026-11-06T10:09:00+00:00"
            ),
        ]

        enriched = enrich_alerts(alerts)

        self.assertEqual(enriched[0]["risk_score"], 65)
        self.assertEqual(enriched[1]["risk_score"], 70)

    def test_alerts_outside_time_window_are_not_correlated(self):
        alerts = [
            self.create_alert(
                rule_id="SSH_BRUTE_FORCE",
                first_seen="2026-11-06T10:00:00+00:00",
                last_seen="2026-11-06T10:04:00+00:00"
            ),
            self.create_alert(
                rule_id="SSH_PASSWORD_SPRAYING",
                first_seen="2026-11-06T10:25:00+00:00",
                last_seen="2026-11-06T10:29:00+00:00"
            ),
        ]

        enriched = enrich_alerts(alerts)

        self.assertEqual(enriched[0]["risk_score"], 50)
        self.assertEqual(enriched[1]["risk_score"], 55)

    def test_alerts_at_exactly_ten_minutes_are_correlated(self):
        alerts = [
            self.create_alert(
                rule_id="SSH_BRUTE_FORCE",
                first_seen="2026-11-06T10:00:00+00:00",
                last_seen="2026-11-06T10:04:00+00:00"
            ),
            self.create_alert(
                rule_id="SSH_PASSWORD_SPRAYING",
                first_seen="2026-11-06T10:14:00+00:00",
                last_seen="2026-11-06T10:18:00+00:00"
            ),
        ]

        enriched = enrich_alerts(alerts)

        self.assertEqual(enriched[0]["risk_score"], 65)
        self.assertEqual(enriched[1]["risk_score"], 70)


if __name__ == "__main__":
    unittest.main(verbosity=2)


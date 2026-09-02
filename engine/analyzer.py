from engine.simulator import SecurityEvent


class ThreatAnalyzer:
    BASE_SEVERITY = {
        "FAILED_SSH_LOGIN": 30,
        "UNAUTHORIZED_API_ACCESS": 50,
        "SUSPICIOUS_FILE_DOWNLOAD": 60,
        "SQL_INJECTION_ATTEMPT": 85,
        "PRIVILEGE_ESCALATION_TRY": 95,
    }

    @classmethod
    def evaluate_event(cls, event: SecurityEvent) -> dict:
        base_score = cls.BASE_SEVERITY.get(event.event_type, 20)

        critical_assets = ["user-db", "system-data"]
        asset_multiplier = 1.2 if event.target_asset in critical_assets else 1.0

        calculated_risk = min(100.0, base_score * asset_multiplier)

        if calculated_risk >= 80:
            threat_level = "CRITICAL"
        elif calculated_risk >= 50:
            threat_level = "HIGH"
        else:
            threat_level = "LOW"

        return {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "target_asset": event.target_asset,
            "risk_score": calculated_risk,
            "threat_level": threat_level,
            "recommended_action": "ISOLATE_HOST" if threat_level == "CRITICAL" else "LOG_AND_MONITOR",
        }
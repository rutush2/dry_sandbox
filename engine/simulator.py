import random
import time
from pydantic import BaseModel


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: float
    source_ip: str
    user_identity: str
    event_type: str
    target_asset: str
    payload_sample: str


class ThreatSimulator:
    EVENT_TYPES = [
        "FAILED_SSH_LOGIN",
        "UNAUTHORIZED_API_ACCESS",
        "SUSPICIOUS_FILE_DOWNLOAD",
        "SQL_INJECTION_ATTEMPT",
        "PRIVILEGE_ESCALATION_TRY",
    ]

    TARGET_ASSETS = ["auth-service", "user-db", "payment-gateway", "internal-wiki"]

    SCENARIOS = {
        "Ransomware Surge": {
            "event_type": "SUSPICIOUS_FILE_DOWNLOAD",
            "count": 15,
            "target": "user-db",
        },
        "DDoS & Auth Flood": {
            "event_type": "FAILED_SSH_LOGIN",
            "count": 20,
            "target": "auth-service",
        },
        "Database Breach Attempt": {
            "event_type": "SQL_INJECTION_ATTEMPT",
            "count": 12,
            "target": "payment-gateway",
        },
    }

    @classmethod
    def generate_event(cls, custom_type: str = None, custom_target: str = None) -> SecurityEvent:
        event_type = custom_type or random.choice(cls.EVENT_TYPES)
        target = custom_target or random.choice(cls.TARGET_ASSETS)

        return SecurityEvent(
            event_id=f"EVT-{random.randint(1000, 9999)}",
            timestamp=time.time(),
            source_ip=f"192.168.1.{random.randint(2, 254)}",
            user_identity=f"user_{random.randint(10, 99)}",
            event_type=event_type,
            target_asset=target,
            payload_sample=f"EXEC_VECTOR [{event_type}] -> {target}",
        )

    @classmethod
    def generate_scenario_batch(cls, scenario_name: str) -> list[SecurityEvent]:
        config = cls.SCENARIOS.get(scenario_name)
        if not config:
            return [cls.generate_event() for _ in range(10)]

        return [
            cls.generate_event(
                custom_type=config["event_type"],
                custom_target=config["target"]
            )
            for _ in range(config["count"])
        ]
import time
from collections import defaultdict


class PolicyEngine:
    def __init__(self, risk_threshold: float = 75.0, attack_frequency_limit: int = 3, time_window_seconds: int = 60):
        self.risk_threshold = risk_threshold
        self.attack_frequency_limit = attack_frequency_limit
        self.time_window_seconds = time_window_seconds
        self.critical_event_tracker = defaultdict(list)

    def process_assessment(self, assessment: dict) -> dict:
        target_asset = assessment.get("target_asset", "unknown")
        risk_score = assessment.get("risk_score", 0.0)
        threat_level = assessment.get("threat_level", "LOW")
        current_time = time.time()

        self.critical_event_tracker[target_asset] = [
            t for t in self.critical_event_tracker[target_asset]
            if current_time - t <= self.time_window_seconds
        ]

        if threat_level == "CRITICAL":
            self.critical_event_tracker[target_asset].append(current_time)

        critical_hits_in_window = len(self.critical_event_tracker[target_asset])

        if critical_hits_in_window >= self.attack_frequency_limit:
            action_taken = "AUTO_QUARANTINE"
            reason = f"Automated Policy Violation: Exceeded {self.attack_frequency_limit} critical hits in {self.time_window_seconds}s window."
        elif risk_score >= self.risk_threshold:
            action_taken = "CONTAINMENT_ACTIVATED"
            reason = f"Risk score ({risk_score}) exceeded risk threshold ({self.risk_threshold})."
        else:
            action_taken = "NO_ACTION"
            reason = "Risk score within acceptable operating parameters."

        return {
            "action_taken": action_taken,
            "reason": reason,
            "recent_critical_hits": critical_hits_in_window,
        }
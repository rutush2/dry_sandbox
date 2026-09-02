from datetime import datetime
from collections import defaultdict


class TimeSeriesAggregator:
    def __init__(self):
        self.hourly_counts = defaultdict(lambda: {"incidents": 0, "blocked": 0, "total_risk": 0.0})
        self.daily_counts = defaultdict(lambda: {"incidents": 0, "critical": 0, "total_risk": 0.0})

    def record_event(self, assessment: dict):
        now = datetime.now()
        hour_key = now.strftime("%H:00")
        day_key = now.strftime("%Y-%m-%d")

        self.hourly_counts[hour_key]["incidents"] += 1
        if assessment.get("action_taken") != "NO_ACTION":
            self.hourly_counts[hour_key]["blocked"] += 1
        self.hourly_counts[hour_key]["total_risk"] += assessment.get("risk_score", 0.0)

        self.daily_counts[day_key]["incidents"] += 1
        if assessment.get("threat_level") == "CRITICAL":
            self.daily_counts[day_key]["critical"] += 1
        self.daily_counts[day_key]["total_risk"] += assessment.get("risk_score", 0.0)

    def get_hourly_today(self) -> list[dict]:
        hourly_data = []
        for hour in range(24):
            hour_str = f"{hour:02d}:00"
            stats = self.hourly_counts.get(hour_str, {"incidents": 0, "blocked": 0, "total_risk": 0.0})
            count = stats["incidents"]
            avg_risk = (stats["total_risk"] / count) if count > 0 else 0.0

            hourly_data.append({
                "time": hour_str,
                "incidents": count,
                "blocked_threats": stats["blocked"],
                "risk_score": round(avg_risk, 1)
            })
        return hourly_data

    def get_daily_history(self) -> list[dict]:
        today_str = datetime.now().strftime("%Y-%m-%d")
        stats = self.daily_counts.get(today_str, {"incidents": 0, "critical": 0, "total_risk": 0.0})
        count = stats["incidents"]
        avg_risk = (stats["total_risk"] / count) if count > 0 else 0.0

        return [{
            "date": today_str,
            "total_incidents": count,
            "critical_threats": stats["critical"],
            "average_risk": round(avg_risk, 1)
        }]

    @staticmethod
    def generate_daily_history() -> list[dict]:
        today_str = datetime.now().strftime("%Y-%m-%d")
        return [{
            "date": today_str,
            "total_incidents": 0,
            "critical_threats": 0,
            "average_risk": 0.0
        }]

    @staticmethod
    def generate_monthly_summary(months: int = 12) -> list[dict]:
        summaries = []
        now = datetime.now()
        for i in range(months - 1, -1, -1):
            year_offset = (now.month - 1 - i) // 12
            month_index = (now.month - 1 - i) % 12 + 1
            calculated_year = now.year + year_offset

            target_date = datetime(calculated_year, month_index, 1)
            month_label = target_date.strftime("%b %Y")

            summaries.append({
                "month": month_label,
                "vulnerabilities_patched": 0,
                "incidents_blocked": 0,
                "mean_time_to_contain_min": 0.0
            })
        return summaries
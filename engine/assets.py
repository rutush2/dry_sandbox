class Asset:
    def __init__(self, asset_name: str, ip_address: str, criticality: str, is_patched: bool, vulnerability_score: float):
        self.asset_name = asset_name
        self.ip_address = ip_address
        self.criticality = criticality
        self.is_patched = is_patched
        self.vulnerability_score = vulnerability_score
        self.status = "VULNERABLE" if vulnerability_score >= 35.0 else "SAFE"

    def to_dict(self) -> dict:
        return {
            "asset_name": self.asset_name,
            "ip_address": self.ip_address,
            "criticality": self.criticality,
            "is_patched": self.is_patched,
            "vulnerability_score": self.vulnerability_score,
            "status": self.status,
        }


class AssetRegistry:
    def __init__(self):
        self.assets = {
            "auth-service": Asset("auth-service", "10.0.1.10", "CRITICAL", False, 65.0),
            "user-db": Asset("user-db", "10.0.1.20", "CRITICAL", False, 80.0),
            "system-gateway": Asset("system-gateway", "10.0.2.5", "CRITICAL", True, 15.0),
            "internal-info": Asset("internal-info", "10.0.4.50", "LOW", True, 10.0),
            "api-gateway": Asset("api-gateway", "10.0.3.15", "HIGH", True, 25.0),
        }

    def get_all_assets(self) -> list[dict]:
        return [asset.to_dict() for asset in self.assets.values()]

    def register_asset(self, asset_name: str, ip_address: str, criticality: str, is_patched: bool, vulnerability_score: float):
        self.assets[asset_name] = Asset(asset_name, ip_address, criticality, is_patched, vulnerability_score)

    def update_asset_posture(self, asset_name: str, threat_level: str, risk_score: float):
        if asset_name in self.assets:
            asset = self.assets[asset_name]
            if asset.status == "QUARANTINED":
                return

            score_boost = 15.0 if threat_level == "CRITICAL" else (10.0 if threat_level == "HIGH" else 5.0)
            asset.vulnerability_score = min(100.0, asset.vulnerability_score + score_boost)

            if asset.vulnerability_score >= 95.0:
                asset.status = "COMPROMISED"
            elif asset.vulnerability_score >= 25.0:
                asset.status = "VULNERABLE"
            else:
                asset.status = "SAFE"

    def patch_asset(self, asset_name: str) -> bool:
        if asset_name in self.assets:
            self.assets[asset_name].is_patched = True
            self.assets[asset_name].vulnerability_score = 10.0
            self.assets[asset_name].status = "SAFE"
            return True
        return False

    def quarantine_asset(self, asset_name: str) -> bool:
        if asset_name in self.assets:
            self.assets[asset_name].status = "QUARANTINED"
            return True
        return False
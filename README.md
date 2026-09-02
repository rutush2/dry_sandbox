```markdown
# Dry Sandbox - Executive Cybersecurity Operations Center

**Dry Sandbox** is an interactive, CISO-grade cybersecurity simulation engine built with Python and Streamlit. It models real-time threat monitoring, dynamic asset posture tracking, automated policy remediation rules, and executive telemetry visualization.

## Key Features

* **Dynamic Asset Inventory:** Real-time posture tracking (`SAFE`, `VULNERABLE`, `COMPROMISED`, `QUARANTINED`) with live vulnerability scoring.
* **Threat Simulation Engine:** Fires realistic cyberattack vectors (SSH brute force, SQL injection, API unauthorized access, privilege escalation).
* **Attack Scenario Batch Generator:** Simulates high-concurrency attack waves (Ransomware Surge, DDoS & Auth Flood, Database Breach Attempts).
* **Stateful CISO Policy Engine:** Sliding-window event evaluation that automatically initiates network isolation (`AUTO_QUARANTINE`) upon exceeding critical threat thresholds.
* **CISO Remediation Panel:** Manual override suite to deploy patches or isolate targeted infrastructure with full audit trail logging.
* **Executive Telemetry & Metrics:** Interactive Plotly charts visualizing 24-hour intraday incident streams, daily risk trajectories, and monthly remediation velocities.

## Project Structure

```text
dry_sandbox/
├── app.py                 # Streamlit UI dashboard and event orchestrator
├── engine/
│   ├── __init__.py        # Package initializer
│   ├── analyzer.py        # Risk scoring and threat evaluation rules
│   ├── assets.py          # Infrastructure asset registry and posture logic
│   ├── metrics.py         # Time-series aggregation for intraday/daily/monthly telemetry
│   ├── policy.py          # Stateful CISO automated containment and quarantine engine
│   └── simulator.py       # Threat event and attack scenario batch generator
├── README.md              # Project documentation
└── requirements.txt       # Dependencies

```

## Requirements

* Python 3.10+
* Streamlit
* Pandas
* Plotly
* Pydantic

## Getting Started

1. **Clone the repository:**
```bash
git clone [https://github.com/YOUR_USERNAME/dry-sandbox.git](https://github.com/YOUR_USERNAME/dry-sandbox.git)
cd dry-sandbox

```


2. **Install dependencies:**
```bash
pip install streamlit pandas plotly pydantic

```


3. **Run the application:**
```bash
streamlit run app.py

```

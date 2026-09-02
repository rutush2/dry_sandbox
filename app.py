import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from engine.analyzer import ThreatAnalyzer
from engine.assets import AssetRegistry
from engine.metrics import TimeSeriesAggregator
from engine.policy import PolicyEngine
from engine.simulator import ThreatSimulator

st.set_page_config(
    page_title="Dry Sandbox - Executive Security Engine", layout="wide"
)

st.title("🛡️Dry Sandbox - Executive Cybersecurity Operations Center")

if "events_history" not in st.session_state:
    st.session_state.events_history = []

if "asset_registry" not in st.session_state:
    st.session_state.asset_registry = AssetRegistry()

if "metrics_aggregator" not in st.session_state:
    st.session_state.metrics_aggregator = TimeSeriesAggregator()

if "hourly_metrics" not in st.session_state:
    st.session_state.hourly_metrics = (
        st.session_state.metrics_aggregator.get_hourly_today()
    )

if "daily_metrics" not in st.session_state:
    st.session_state.daily_metrics = (
        st.session_state.metrics_aggregator.get_daily_history()
    )

if "monthly_metrics" not in st.session_state:
    st.session_state.monthly_metrics = (
        TimeSeriesAggregator.generate_monthly_summary()
    )

st.sidebar.header("CISO Policy Controls")
risk_threshold = st.sidebar.slider(
    "Automated Containment Threshold", 10.0, 100.0, 75.0, 5.0
)
policy_engine = PolicyEngine(risk_threshold=risk_threshold)

st.sidebar.markdown("---")
st.sidebar.header("Attack Scenario Batch Generator")

selected_scenario = st.sidebar.selectbox(
    "Select Cyber Scenario", list(ThreatSimulator.SCENARIOS.keys())
)

if st.sidebar.button("Execute Attack Scenario"):
    events_batch = ThreatSimulator.generate_scenario_batch(selected_scenario)
    critical_count = 0

    for raw_event in events_batch:
        assessment = ThreatAnalyzer.evaluate_event(raw_event)
        assessment["target_asset"] = raw_event.target_asset
        mitigation = policy_engine.process_assessment(assessment)

        st.session_state.metrics_aggregator.record_event({
            "risk_score": assessment["risk_score"],
            "threat_level": assessment["threat_level"],
            "action_taken": mitigation["action_taken"],
        })

        if mitigation["action_taken"] == "AUTO_QUARANTINE":
            st.session_state.asset_registry.quarantine_asset(
                raw_event.target_asset
            )
        else:
            st.session_state.asset_registry.update_asset_posture(
                raw_event.target_asset,
                assessment["threat_level"],
                assessment["risk_score"],
            )

        if assessment["threat_level"] == "CRITICAL":
            critical_count += 1

        event_record = {
            "ID": raw_event.event_id,
            "Type": raw_event.event_type,
            "Target": raw_event.target_asset,
            "Risk Score": assessment["risk_score"],
            "Threat Level": assessment["threat_level"],
            "Action Taken": mitigation["action_taken"],
        }
        st.session_state.events_history.insert(0, event_record)

    st.sidebar.error(
        f"Executed '{selected_scenario}' with {len(events_batch)} events ({critical_count} CRITICAL)."
    )
    st.rerun()


st.sidebar.header("Register New Asset")
with st.sidebar.form("add_asset_form"):
    new_asset_name = st.text_input("Asset Name", "api-gateway")
    new_ip = st.text_input("IP Address", "10.0.3.15")
    new_criticality = st.selectbox("Criticality", ["CRITICAL", "HIGH", "LOW"])
    new_patched = st.checkbox("Patched", value=True)
    new_vuln_score = st.slider("Vulnerability Score", 0.0, 100.0, 25.0)
    submitted = st.form_submit_button("Add Asset")
    if submitted:
        st.session_state.asset_registry.register_asset(
            new_asset_name,
            new_ip,
            new_criticality,
            new_patched,
            new_vuln_score,
        )
        st.sidebar.success(f"Asset '{new_asset_name}' added successfully.")

if st.sidebar.button("Initiated Threat Simulation"):
    raw_event = ThreatSimulator.generate_event()
    assessment = ThreatAnalyzer.evaluate_event(raw_event)
    assessment["target_asset"] = raw_event.target_asset
    mitigation = policy_engine.process_assessment(assessment)

    st.session_state.metrics_aggregator.record_event({
        "risk_score": assessment["risk_score"],
        "threat_level": assessment["threat_level"],
        "action_taken": mitigation["action_taken"],
    })

    if mitigation["action_taken"] == "AUTO_QUARANTINE":
        st.session_state.asset_registry.quarantine_asset(raw_event.target_asset)
    else:
        st.session_state.asset_registry.update_asset_posture(
            raw_event.target_asset,
            assessment["threat_level"],
            assessment["risk_score"],
        )

    event_record = {
        "ID": raw_event.event_id,
        "Type": raw_event.event_type,
        "Target": raw_event.target_asset,
        "Risk Score": assessment["risk_score"],
        "Threat Level": assessment["threat_level"],
        "Action Taken": mitigation["action_taken"],
    }
    st.session_state.events_history.insert(0, event_record)
    st.rerun()

tab1, tab2, tab3 = st.tabs([
    "Asset Posture & Vulnerabilities",
    "Live Telemetry & Logs",
    "Daily & Monthly Trends",
])

with tab1:
    st.subheader("Infrastructure Asset Inventory & Security Status")
    assets_df = pd.DataFrame(st.session_state.asset_registry.get_all_assets())

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Monitored Assets", len(assets_df))
    c2.metric(
        "Safe & Secure Assets", len(assets_df[assets_df["status"] == "SAFE"])
    )
    c3.metric(
        "Vulnerable Assets", len(assets_df[assets_df["status"] == "VULNERABLE"])
    )
    c4.metric(
        "Compromised / Quarantined",
        len(
            assets_df[assets_df["status"].isin(["COMPROMISED", "QUARANTINED"])]
        ),
    )

    st.dataframe(assets_df, use_container_width=True)

    fig_assets = px.bar(
        assets_df,
        x="asset_name",
        y="vulnerability_score",
        color="status",
        title="Asset Vulnerability Score & Exposure Level",
        color_discrete_map={
            "SAFE": "#2ECC71",
            "VULNERABLE": "#F39C12",
            "COMPROMISED": "#E74C3C",
            "QUARANTINED": "#9B59B6",
        },
    )
    st.plotly_chart(fig_assets, use_container_width=True)

    st.markdown("---")
    st.subheader("CISO Remediation & Quarantine Panel")

    col_act1, col_act2 = st.columns(2)

    with col_act1:
        st.markdown("### Apply Security Patch")
        vulnerable_assets = [
            a["asset_name"]
            for a in st.session_state.asset_registry.get_all_assets()
            if a["status"] != "SAFE"
        ]
        if vulnerable_assets:
            target_patch = st.selectbox(
                "Select Asset to Patch", vulnerable_assets, key="patch_select"
            )
            if st.button("Deploy Patch & Secure Asset"):
                st.session_state.asset_registry.patch_asset(target_patch)

                st.session_state.events_history.insert(
                    0,
                    {
                        "ID": f"MAN-{len(st.session_state.events_history) + 1:04d}",
                        "Type": "MANUAL_REMEDIATION",
                        "Target": target_patch,
                        "Risk Score": 0.0,
                        "Threat Level": "INFO",
                        "Action Taken": "PATCH_DEPLOYED",
                    },
                )
                st.success(
                    f"Security patch successfully applied to '{target_patch}'. Status set to SAFE."
                )
                st.rerun()
        else:
            st.info(
                "All monitored assets are currently fully patched and secure."
            )

    with col_act2:
        st.markdown("### Isolate Asset (Quarantine)")
        all_asset_names = [
            a["asset_name"]
            for a in st.session_state.asset_registry.get_all_assets()
            if a["status"] != "QUARANTINED"
        ]
        if all_asset_names:
            target_quarantine = st.selectbox(
                "Select Asset to Quarantine",
                all_asset_names,
                key="quarantine_select",
            )
            if st.button("Isolate Asset from Network"):
                st.session_state.asset_registry.quarantine_asset(
                    target_quarantine
                )

                st.session_state.events_history.insert(
                    0,
                    {
                        "ID": f"MAN-{len(st.session_state.events_history) + 1:04d}",
                        "Type": "MANUAL_ISOLATION",
                        "Target": target_quarantine,
                        "Risk Score": 100.0,
                        "Threat Level": "CRITICAL",
                        "Action Taken": "MANUAL_QUARANTINE",
                    },
                )
                st.warning(
                    f"Asset '{target_quarantine}' has been isolated and placed in QUARANTINED state."
                )
                st.rerun()
        else:
            st.info("All assets are currently in QUARANTINED state.")

with tab2:
    st.subheader("Real-Time Threat Execution Feed")
    if st.session_state.events_history:
        events_df = pd.DataFrame(st.session_state.events_history)
        st.dataframe(events_df, use_container_width=True)

        fig_events = px.pie(
            events_df,
            names="Threat Level",
            title="Threat Severity Distribution",
            color="Threat Level",
            color_discrete_map={
                "LOW": "#3498DB",
                "HIGH": "#F39C12",
                "CRITICAL": "#E74C3C",
            },
        )
        st.plotly_chart(fig_events, use_container_width=True)
    else:
        st.info("Launch a threat simulation from the sidebar to view live logs.")


with tab3:
    st.subheader("Intraday Threat Breakdown (Live 24-Hour Stream)")

    live_hourly = st.session_state.metrics_aggregator.get_hourly_today()
    hourly_df = pd.DataFrame(live_hourly)

    fig_hourly = go.Figure()
    fig_hourly.add_trace(
        go.Bar(
            x=hourly_df["time"],
            y=hourly_df["incidents"],
            name="Total Incidents",
            marker_color="#3498DB",
        )
    )
    fig_hourly.add_trace(
        go.Bar(
            x=hourly_df["time"],
            y=hourly_df["blocked_threats"],
            name="Contained Threats",
            marker_color="#2ECC71",
        )
    )
    fig_hourly.update_layout(
        title="Real-Time 24-Hour Intraday Incident Stream",
        barmode="group",
        xaxis_title="Hour of Day",
        yaxis_title="Event Count",
    )
    st.plotly_chart(fig_hourly, use_container_width=True)

    st.subheader("Daily Risk Trajectory & Critical Incidents")

    live_daily = st.session_state.metrics_aggregator.get_daily_history()
    daily_df = pd.DataFrame(live_daily)

    fig_daily = go.Figure()
    fig_daily.add_trace(
        go.Scatter(
            x=daily_df["date"],
            y=daily_df["average_risk"],
            mode="lines+markers",
            name="Avg System Risk Score",
            line=dict(color="#E74C3C", width=3),
        )
    )
    fig_daily.add_trace(
        go.Bar(
            x=daily_df["date"],
            y=daily_df["critical_threats"],
            name="Critical Incidents Detected",
            opacity=0.4,
            marker_color="#F39C12",
        )
    )
    fig_daily.update_layout(
        title="Live System Risk & Critical Incident Trajectory",
        xaxis_title="Date",
        yaxis_title="Metric Value",
        xaxis=dict(type="category"),
    )
    st.plotly_chart(fig_daily, use_container_width=True)

    st.subheader("Monthly Executive Summary & Remediation Velocity")
    monthly_df = pd.DataFrame(st.session_state.monthly_metrics)

    col_m1, col_m2 = st.columns(2)
    with col_m1:
        fig_monthly_patch = px.bar(
            monthly_df,
            x="month",
            y="vulnerabilities_patched",
            title="Monthly Vulnerabilities Remediated",
        )
        st.plotly_chart(fig_monthly_patch, use_container_width=True)

    with col_m2:
        fig_mttr = px.line(
            monthly_df,
            x="month",
            y="mean_time_to_contain_min",
            title="Mean Time to Contain (MTTC - Minutes)",
            markers=True,
        )
        st.plotly_chart(fig_mttr, use_container_width=True)
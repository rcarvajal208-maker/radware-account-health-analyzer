import pandas as pd
import streamlit as st
from modules.entitlement_profiles import is_module_licensed

HIGH_RISK_DISABLED_MODULES = [
    "SQL Injection",
    "Signature Protection",
    "RFC Violation Protection",
    "JSON Validation",
    "SSRF",
    "Path Access",
]

MEDIUM_RISK_DISABLED_MODULES = [
    "Source Blocking",
    "ERT Feed",
    "Anonymous Proxy / TOR",
    "Geo Blocking",
    "Access Control",
    "Rate Limit",
    "API Protection",
    "ATO",
    "Web DDoS",
    "Client-side Protection",
]

VISIBILITY_MODULES = [
    "Export Security Logs",
    "Export Access Logs",
]


def is_disabled(value):
    if value is None:
        return False

    value = str(value).lower()

    return (
        "disabled" in value
        or "disable" in value
        or "not configured" in value
        or value == "false"
    )


def is_report_only(value):
    if value is None:
        return False

    value = str(value).lower()

    return "report only" in value or "report_only" in value or "passive" in value


def is_enabled(value):
    if value is None:
        return False

    value = str(value).lower()

    return (
        "enabled" in value
        or "active" in value
        or "blocking" in value
        or "configured" in value
        or value == "true"
    )


def add_recommendation(rows, app_name, severity, finding, recommendation):
    rows.append({
        "Application": app_name,
        "Severity": severity,
        "Finding": finding,
        "Recommendation": recommendation,
    })


def build_security_recommendations(adoption_df):
    rows = []

    if adoption_df is None or adoption_df.empty:
        return pd.DataFrame(rows)

    for _, row in adoption_df.iterrows():
        app_name = row.get("Application Name", "Unknown Application")

        security_policy = row.get("Security Policy Applied")

        if is_disabled(security_policy):
            add_recommendation(
                rows,
                app_name,
                "High",
                "Application is not governed by a Security Policy.",
                "Associate this application with a Security Policy to centralize protection management.",
            )

        for module in HIGH_RISK_DISABLED_MODULES:
            if not is_module_licensed(module):
                continue
            value = row.get(module)

            if is_disabled(value):
                add_recommendation(
                    rows,
                    app_name,
                    "High",
                    f"{module} is disabled or not configured.",
                    f"Review and enable {module}. Prefer Blocking mode after validation.",
                )

            elif is_report_only(value):
                add_recommendation(
                    rows,
                    app_name,
                    "Medium",
                    f"{module} is running in Report Only or Passive mode.",
                    f"Review events and consider moving {module} to Blocking mode.",
                )

        for module in MEDIUM_RISK_DISABLED_MODULES:
            if not is_module_licensed(module):
                continue
            value = row.get(module)

            if is_disabled(value):
                add_recommendation(
                    rows,
                    app_name,
                    "Medium",
                    f"{module} is disabled or not configured.",
                    f"Evaluate enabling {module} based on the application exposure and risk profile.",
                )

            elif is_report_only(value):
                add_recommendation(
                    rows,
                    app_name,
                    "Low",
                    f"{module} is running in Report Only or Passive mode.",
                    f"Validate impact and consider moving {module} to Blocking mode.",
                )

        security_bypass = row.get("Security Bypass")

        if is_module_licensed("Security Bypass") and is_enabled(security_bypass):
            add_recommendation(
                rows,
                app_name,
                "Medium",
                "Security Bypass is configured.",
                "Review bypass entries and confirm each one has a valid business justification.",
            )

        for module in VISIBILITY_MODULES:
            if not is_module_licensed(module):
                continue
            value = row.get(module)

            if is_disabled(value):
                add_recommendation(
                    rows,
                    app_name,
                    "Low",
                    f"{module} is disabled.",
                    f"Enable {module} to improve monitoring, troubleshooting and forensic visibility.",
                )

    return pd.DataFrame(rows)


def calculate_recommendation_metrics(recommendations_df):
    if recommendations_df.empty:
        return {
            "Total Recommendations": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
        }

    return {
        "Total Recommendations": len(recommendations_df),
        "High": len(recommendations_df[recommendations_df["Severity"] == "High"]),
        "Medium": len(recommendations_df[recommendations_df["Severity"] == "Medium"]),
        "Low": len(recommendations_df[recommendations_df["Severity"] == "Low"]),
    }


def style_severity(value):
    if value == "High":
        return "background-color: rgba(127, 29, 29, 0.55); color: white;"
    if value == "Medium":
        return "background-color: rgba(113, 63, 18, 0.55); color: white;"
    if value == "Low":
        return "background-color: rgba(20, 83, 45, 0.35); color: white;"
    return ""


def render_security_recommendations_dashboard():
    st.subheader("Security Recommendations")

    if "application_adoption_df" not in st.session_state:
        st.warning("Application Adoption data is not available yet. Run the Application Adoption module first.")
        return

    adoption_df = st.session_state["application_adoption_df"]

    recommendations_df = build_security_recommendations(adoption_df)

    app_options = ["All Applications"] + sorted(
        recommendations_df["Application"].dropna().unique().tolist()
    )

    selected_app = st.selectbox(
        "Filter by application",
        app_options
    )

    if selected_app != "All Applications":
        recommendations_df = recommendations_df[
            recommendations_df["Application"] == selected_app
        ]

    if selected_app == "All Applications":
        st.caption(
            f"Showing {len(recommendations_df)} recommendations across all applications"
        )
    else:
        st.caption(
            f"Showing {len(recommendations_df)} recommendations for {selected_app}"
        )

    if recommendations_df.empty:
        st.success("No security recommendations detected based on current rules.")
        return

    metrics = calculate_recommendation_metrics(recommendations_df)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Recommendations", metrics["Total Recommendations"])
    col2.metric("High Severity", metrics["High"])
    col3.metric("Medium Severity", metrics["Medium"])
    col4.metric("Low Severity", metrics["Low"])

    severity_filter = st.multiselect(
        "Filter by severity",
        ["High", "Medium", "Low"],
        default=["High", "Medium", "Low"]
    )

    filtered_df = recommendations_df[
        recommendations_df["Severity"].isin(severity_filter)
    ]

    st.dataframe(
        filtered_df.style.map(style_severity, subset=["Severity"]),
        use_container_width=True,
        hide_index=True
    )

    csv = filtered_df.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="Download Security Recommendations CSV",
        data=csv,
        file_name="security_recommendations.csv",
        mime="text/csv",
        key="download_security_recommendations_csv"
    )
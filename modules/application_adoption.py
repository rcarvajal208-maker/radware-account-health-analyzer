import pandas as pd
import streamlit as st
from modules.entitlement_profiles import filter_columns_by_entitlement
from ui_feedback import radware_inline_loader

PRIORITY_COLUMNS = [
    "Application Name",
    "Application ID",
    "Deployment Status",
    "Security Policy Applied",
    "Security Policy Name",
    "Data Source",
    "RFC Violation Protection",
    "Signature Protection",
    "SQL Injection",
    "Path Access",
    "JSON Validation",
    "SSRF",
    "Access Control",
    "Geo Blocking",
    "Security Bypass",
    "Anonymous Proxy / TOR",
    "Source Blocking",
    "ERT Feed",
    "HTTP Protection / Rules",
    "Bot Manager",
    "API Protection",
    "ATO",
    "Rate Limit",
    "API Discovery",
    "BLA Protection",
    "Client-side Protection",
    "Web DDoS",
    "Export Security Logs",
    "Export Access Logs",
    "GraphQL",
    "CDN",
]

STATUS_DISPLAY_NAMES = {
    True: "🟢 Enabled",
    False: "🔴 Disabled",
    "ACTIVE": "🟢 Active",
    "PASSIVE": "🟡 Passive",
    "DISABLE": "🔴 Disabled",
    "DISABLED": "🔴 Disabled",
    "ENABLE": "🟢 Enabled",
    "ENABLED": "🟢 Enabled",
    "BLOCK": "🟢 Blocking",
    "BLOCK_AND_REPORT": "🟢 Blocking",
    "ENABLE_AND_REPORT": "🟢 Blocking",
    "REPORT_ONLY": "🟡 Report Only",
    "Configured": "🟢 Configured",
    "Not Configured": "🔴 Not Configured",
    "N/A": "N/A",
}


def get_value(data, path, default=None):
    current = data

    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)

    return current if current is not None else default


def display_status(value):
    return STATUS_DISPLAY_NAMES.get(value, value)


def get_application_detail(client, app_id):
    try:
        return client.get(f"/v1/gms/applications/{app_id}")
    except Exception:
        return None


def get_security_policy_by_app(client, app_id):
    try:
        return client.get(f"/v1/configuration/securityPolicies/applications/{app_id}")
    except Exception:
        return None


def extract_policy_protections(policy):
    if not isinstance(policy, dict):
        return {}

    protections = policy.get("protections", {})

    if isinstance(protections, dict):
        return protections

    if isinstance(protections, list):
        result = {}
        for item in protections:
            p_type = item.get("type")
            if p_type:
                result[p_type] = item
        return result

    return {}


def get_policy_status(policy, keys, default="N/A"):
    protections = extract_policy_protections(policy)

    for key in keys:
        item = protections.get(key)

        if isinstance(item, dict):
            status = (
                item.get("status")
                or get_value(item, ["config", "status"])
                or item.get("mode")
                or get_value(item, ["config", "mode"])
            )

            if status:
                return status

            if item.get("notConfigured") is True:
                return "Not Configured"

            if item.get("notConfigured") is False:
                return "Configured"

            return default

    return default


def get_app_status(app, paths, default="N/A"):
    for path in paths:
        value = get_value(app, path)
        if value is not None:
            return value

    return default

def get_bla_protection_status(client, app_id):
    endpoint = (
        f"/api/waf/ng/analytics/businessLogicActivity/"
        f"{app_id}/getGraphRules"
    )

    try:
        result = client.get_console(endpoint)

        if isinstance(result, dict):
            if len(result) > 1:
                return "ACTIVE"
            return "DISABLED"

        if isinstance(result, list):
            if len(result) > 1:
                return "ACTIVE"
            return "DISABLED"

        return "N/A"

    except Exception:
        return "N/A"

def get_security_bypass_status_from_policy(policy):
    protections = extract_policy_protections(policy)
    security_bypass = protections.get("securityBypass", {})

    rules = get_value(security_bypass, ["config", "rules"], [])

    if isinstance(rules, list) and len(rules) > 0:
        return "Configured"

    if isinstance(security_bypass, dict):
        if security_bypass.get("notConfigured") is False:
            return "Configured"
        if security_bypass.get("notConfigured") is True:
            return "Not Configured"

    return "Not Configured"


def get_security_bypass_status_from_app(app):
    access_rules = get_value(
        app,
        ["featuresData", "wafFeatureData", "accessRules", "accessRules"],
        []
    )

    if isinstance(access_rules, list) and len(access_rules) > 0:
        return "Configured"

    bypass_enabled = get_app_status(
        app,
        [
            ["cwafBypassEnabled"],
            ["awBypassEnabled"],
        ],
        False
    )

    if bypass_enabled is True:
        return "Configured"

    return "Not Configured"


def build_display_dataframe(df):
    display_df = df.copy()

    for column in display_df.columns:
        display_df[column] = display_df[column].map(display_status)

    return display_df


def style_security_policy_rows(row):
    security_policy_value = row.get("Security Policy Applied", "")

    if isinstance(security_policy_value, str) and "🟢" in security_policy_value:
        return ["background-color: rgba(20, 83, 45, 0.38); color: white;"] * len(row)

    if isinstance(security_policy_value, str) and "🔴" in security_policy_value:
        return ["background-color: rgba(127, 29, 29, 0.38); color: white;"] * len(row)

    return [""] * len(row)


def normalize_application_adoption(client, applications):
    rows = []

    if not applications:
        return pd.DataFrame(rows)

    progress = st.progress(0, text="Loading application security adoption...")

    loader_placeholder = st.empty()

    with loader_placeholder.container():
        radware_inline_loader("Loading application security adoption...")

    progress = st.progress(0)

    for index, app_summary in enumerate(applications):
        app_id = app_summary.get("id")

        app = get_application_detail(client, app_id) or app_summary
        policy = get_security_policy_by_app(client, app_id)

        has_policy = isinstance(policy, dict) and bool(policy.get("id") or policy.get("name"))
        data_source = "Security Policy" if has_policy else "Application Config"
        policy_name = policy.get("name") if has_policy else "N/A"

        if has_policy:
            rfc_violation = get_policy_status(policy, ["rfcViolationProtection"])
            signature_protection = get_policy_status(policy, ["signatureBasedProtection"])
            sql_injection = get_policy_status(policy, ["sqlInjectionProtection"])
            path_access = get_policy_status(policy, ["pathAccess"])
            json_validation = get_policy_status(policy, ["jsonValidationProtection"])
            ssrf = get_policy_status(policy, ["ssrfProtection"])
            access_control = get_policy_status(policy, ["accessControlList"])
            geo_blocking = get_policy_status(policy, ["geoBlocking"])
            security_bypass = get_security_bypass_status_from_policy(policy)
            anonymous_proxy = get_policy_status(policy, ["ipReputation", "anonymousProxy", "tor"])
            source_blocking = get_policy_status(policy, ["sourceBlocking"])
            ert_feed = get_policy_status(policy, ["ertActiveAttackersFeed", "attackersFeed"])

            http_protection_rules = get_policy_status(
                policy,
                [
                    "httpManagement",
                    "httpProtection",
                    "httpProtocolComplianceProtection",
                    "rfcViolationProtection",
                ],
            )

            bot_manager = get_policy_status(policy, ["botManagerStatus", "badBotMitigation"])
            ato_protection = get_policy_status(policy, ["credentialsCracking"])
            rate_limit = get_policy_status(policy, ["rateLimit"])

        else:
            rfc_violation = get_app_status(
                app,
                [["featuresData", "wafFeatureData", "protectionConfiguration", "httpProtocolComplianceProtection", "protectionStatus"]],
            )

            signature_protection = get_app_status(
                app,
                [["featuresData", "wafFeatureData", "protectionConfiguration", "vulnerabilityProtection", "protectionStatus"]],
            )

            sql_injection = get_app_status(
                app,
                [["featuresData", "wafFeatureData", "protectionConfiguration", "databaseProtection", "protectionStatus"]],
            )

            path_access = get_app_status(
                app,
                [
                    ["featuresData", "wafFeatureData", "protectionConfiguration", "allowedFileExtensionProtection", "protectionStatus"],
                    ["pathAccessProtectionAvailability"],
                ],
            )

            json_validation = get_app_status(app, [["jsonParsing", "jsonParsingMode"]])

            ssrf = get_app_status(
                app,
                [
                    ["featuresData", "wafFeatureData", "protectionConfiguration", "ssrfProtection", "protectionStatus"],
                    ["ssrfEnabled"],
                ],
            )

            access_control = get_app_status(
                app,
                [["featuresData", "wafFeatureData", "accessControlList", "mode"]],
            )

            geo_blocking = get_app_status(
                app,
                [
                    ["geoBlocking", "geoBlockingMode"],
                    ["geoBlockingEnabled"],
                ],
            )

            security_bypass = get_security_bypass_status_from_app(app)

            anonymous_proxy = get_app_status(
                app,
                [["featuresData", "wafFeatureData", "protectionConfiguration", "ipReputationProtection", "protectionStatus"]],
            )

            source_blocking = get_app_status(app, [["sourceBlockingEnabled"]])

            ert_feed = get_app_status(
                app,
                [
                    ["attackersFeed", "attackersFeedMode"],
                    ["attackersFeedEnabled"],
                ],
            )

            http_protection_rules = get_app_status(
                app,
                [
                    ["advancedRulesEnabled"],
                    ["advancedRules", "rulesLimit"],
                ],
            )

            bot_manager = get_app_status(app, [["antibotEnabled"]])
            ato_protection = "N/A"

            rate_limit = get_app_status(
                app,
                [
                    ["rateLimit", "rateLimitMode"],
                    ["rateLimitEnabled"],
                ],
            )

        # API related fields must come from Application Config
        api_protection = get_app_status(
            app,
            [
                ["apiProtection", "status"],
                ["apiProtectionEnabled"],
            ],
        )

        api_discovery = get_app_status(
            app,
            [
                ["apiProtection", "apiDiscovery"],
                ["apiDiscoveryEnabled"],
            ],
            False,
        )

        bla_protection = get_bla_protection_status(client, app_id)

        export_security_logs = app.get("securityEventsExportEnabled", False)
        export_access_logs = app.get("accessLogsEnabled", False)
        graphql = get_value(app, ["graphQLConfiguration", "status"], "N/A")
        cdn = get_value(app, ["cdnConfiguration", "enabled"], False)

        row = {
            "Application Name": app.get("name"),
            "Application ID": app.get("id"),
            "Deployment Status": app.get("deploymentStatus"),
            "Security Policy Applied": has_policy,
            "Security Policy Name": policy_name,
            "Data Source": data_source,

            "RFC Violation Protection": rfc_violation,
            "Signature Protection": signature_protection,
            "SQL Injection": sql_injection,
            "Path Access": path_access,
            "JSON Validation": json_validation,
            "SSRF": ssrf,
            "Access Control": access_control,
            "Geo Blocking": geo_blocking,
            "Security Bypass": security_bypass,
            "Anonymous Proxy / TOR": anonymous_proxy,
            "Source Blocking": source_blocking,
            "ERT Feed": ert_feed,
            "HTTP Protection / Rules": http_protection_rules,
            "Bot Manager": bot_manager,

            "API Protection": api_protection,
            "ATO": ato_protection,
            "Rate Limit": rate_limit,
            "API Discovery": api_discovery,
            "BLA Protection": bla_protection,
            "Export Security Logs": export_security_logs,
            "Export Access Logs": export_access_logs,
            "GraphQL": graphql,
            "CDN": cdn,
            "Web DDoS": get_app_status(
                app,
                [["featuresData", "wafFeatureData", "protectionConfiguration", "ddosProtection", "protectionStatus"]],
            ),

            "Client-side Protection": get_app_status(
                app,
                [
                    ["clientSideProtectionEnabled"],
                    ["clientSideProtection", "status"],
                    ["cspEnabled"],
                ],
            ),
            "DDoS": get_app_status(
                app,
                [["featuresData", "wafFeatureData", "protectionConfiguration", "ddosProtection", "protectionStatus"]],
            ),
        }

        rows.append(row)

        progress.progress(
            (index + 1) / len(applications),
            text="Loading application security adoption..."
        )

    loader_placeholder.empty()

    df = pd.DataFrame(rows)

    ordered_columns = [
        col for col in PRIORITY_COLUMNS if col in df.columns
    ] + [
        col for col in df.columns if col not in PRIORITY_COLUMNS
    ]

    return df[ordered_columns]

def count_enabled(df, column, values=None):
    if column not in df.columns:
        return 0

    if values is None:
        values = [True, "ACTIVE", "ENABLE", "ENABLED", "BLOCK_AND_REPORT"]

    return len(df[df[column].isin(values)])

def calculate_adoption_metrics(df):
    if df.empty:
        return {
            "Total Apps": 0,
            "Apps with Security Policy": 0,
            "Apps without Security Policy": 0,
            "API Protection Enabled": 0,
            "API Discovery Enabled": 0,
            "BLA Protection Enabled": 0,
            "Export Security Logs Enabled": 0,
            "Export Access Logs Enabled": 0,
            "CDN Enabled": 0,
            "Source Blocking Enabled": 0,
        }

    return {
        "Total Apps": len(df),
        "Apps with Security Policy": count_enabled(df, "Security Policy Applied", [True]),
        "Apps without Security Policy": count_enabled(df, "Security Policy Applied", [False]),
        "API Protection Enabled": count_enabled(df, "API Protection"),
        "API Discovery Enabled": count_enabled(df, "API Discovery", [True]),
        "BLA Protection Enabled": count_enabled(df, "BLA Protection"),
        "Export Security Logs Enabled": count_enabled(df, "Export Security Logs", [True]),
        "Export Access Logs Enabled": count_enabled(df, "Export Access Logs", [True]),
        "CDN Enabled": count_enabled(df, "CDN", [True]),
        "Source Blocking Enabled": count_enabled(df, "Source Blocking", [True, "ACTIVE", "ENABLE", "ENABLED", "BLOCK_AND_REPORT", "Configured"]),
    }

def render_application_adoption_dashboard(applications_response, client):
    st.subheader("Application Security Adoption")

    applications = applications_response.get("content", [])


    if "application_adoption_df" not in st.session_state:
        adoption_df = normalize_application_adoption(client, applications)
        st.session_state["application_adoption_df"] = adoption_df

    df = st.session_state["application_adoption_df"]

    df = filter_columns_by_entitlement(df)

    if df.empty:
        st.warning("No application adoption data found.")
        return

    metrics = calculate_adoption_metrics(df)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Applications", metrics["Total Apps"])
    col2.metric("Apps with Security Policy", metrics["Apps with Security Policy"])
    col3.metric("Apps without Security Policy", metrics["Apps without Security Policy"])
    col4.metric("API Protection Enabled", metrics["API Protection Enabled"])

    col5, col6, col7, col8 = st.columns(4)
    col5.metric("API Discovery Enabled", metrics["API Discovery Enabled"])
    col6.metric("BLA Protection Enabled", metrics["BLA Protection Enabled"])
    col7.metric("Security Logs Export Enabled", metrics["Export Security Logs Enabled"])
    col8.metric("Access Logs Export Enabled", metrics["Export Access Logs Enabled"])

    col9, col10 = st.columns(2)
    col9.metric("CDN Enabled", metrics["CDN Enabled"])
    col10.metric("Source Blocking Enabled", metrics["Source Blocking Enabled"])

    st.markdown("### Application Security Adoption Matrix")

    display_df = build_display_dataframe(df)

    styled_df = display_df.style.apply(
        style_security_policy_rows,
        axis=1
    )

    st.dataframe(
        styled_df,
        use_container_width=True,
        hide_index=True
    )

    st.caption(
        "Rows in green are governed by Security Policy. "
        "Rows in red are using Application Config. "
        "Cell icons indicate the module state."
    )

    csv = df.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="Download Application Adoption CSV",
        data=csv,
        file_name="application_security_adoption.csv",
        mime="text/csv",
        key="download_application_adoption_csv"
    )
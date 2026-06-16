import streamlit as st


BASE_COLUMNS = [
    "Application Name",
    "Application ID",
    "Deployment Status",
    "Security Policy Applied",
    "Security Policy Name",
    "Data Source",
    "Export Security Logs",
]


ENTITLEMENT_PROFILES = {
    "Default / Unknown": None,

    "Standard": [
        "RFC Violation Protection",
        "Signature Protection",
        "SQL Injection",
        "Access Control",
        "Geo Blocking",
        "Bot Manager",
        "Rate Limit",
    ],

    "Advanced": [
        "RFC Violation Protection",
        "Signature Protection",
        "SQL Injection",
        "Access Control",
        "Geo Blocking",
        "Bot Manager",
        "Rate Limit",
        "Path Access",
        "Source Blocking",
        "ERT Feed",
        "Client-side Protection",
    ],

    "Complete": [
        "RFC Violation Protection",
        "Signature Protection",
        "SQL Injection",
        "Access Control",
        "Geo Blocking",
        "Rate Limit",
        "Path Access",
        "Source Blocking",
        "ERT Feed",
        "Bot Manager",
        "API Protection",
        "Client-side Protection",
    ],

    "Enterprise": [
        "RFC Violation Protection",
        "Signature Protection",
        "SQL Injection",
        "Path Access",
        "JSON Validation",
        "Access Control",
        "Geo Blocking",
        "Security Bypass",
        "HTTP Protection / Rules",
        "API Protection",
        "BLA Protection",
    ],
}


ADDON_MODULES = {
    "Bot Manager": ["Bot Manager"],
    "API Security": ["API Protection", "API Discovery", "BLA Protection"],
    "Access Logs": ["Export Access Logs"],
    "CDN": ["CDN"],
    "Web DDoS": ["Web DDoS"],
    "Client-side Protection": ["Client-side Protection"], 
}


def render_entitlement_selector():
    st.sidebar.divider()
    st.sidebar.subheader("Entitlement Profile")

    profile = st.sidebar.selectbox(
        "Application Protection Plan",
        list(ENTITLEMENT_PROFILES.keys()),
        index=0
    )

    addons = st.sidebar.multiselect(
        "Add-ons",
        list(ADDON_MODULES.keys())
    )

    st.session_state["entitlement_profile"] = profile
    st.session_state["entitlement_addons"] = addons
    st.session_state["licensed_modules"] = get_licensed_modules(profile, addons)


def get_licensed_modules(profile, addons):
    if profile == "Default / Unknown":
        return None

    licensed = set(BASE_COLUMNS)

    for module in ENTITLEMENT_PROFILES.get(profile, []):
        licensed.add(module)

    for addon in addons:
        for module in ADDON_MODULES.get(addon, []):
            licensed.add(module)

    return list(licensed)


def filter_columns_by_entitlement(df):
    licensed_modules = st.session_state.get("licensed_modules")

    if licensed_modules is None:
        return df

    return df[[column for column in df.columns if column in licensed_modules]]


def is_module_licensed(module_name):
    licensed_modules = st.session_state.get("licensed_modules")

    if licensed_modules is None:
        return True

    return module_name in licensed_modules
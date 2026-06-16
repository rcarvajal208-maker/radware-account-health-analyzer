import streamlit as st
from config import BASE_URL
from radware_client import RadwareClient
from modules.application_adoption import render_application_adoption_dashboard
from modules.security_recommendations import render_security_recommendations_dashboard
from modules.entitlement_profiles import render_entitlement_selector
from ui_feedback import radware_working, radware_success

st.set_page_config(
    page_title="Radware Account Health Analyzer",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Radware Account Health Analyzer")
st.caption("Read-only dashboard for account status, usage and protection visibility.")

with st.sidebar:
    st.header("Connection")

    api_key = st.text_input("API Key", type="password")
    context = st.text_input("Application Protection / Context ID")

    context_type = st.selectbox(
        "Context Type",
        ["Application Protection", "Infrastructure Protection"]
    )

    connect = st.button("Test Connection")
    render_entitlement_selector()

if connect:
    if not api_key or not context:
        st.error("Please provide API Key and Context ID.")
    else:
        client = RadwareClient(
            api_key=api_key,
            context=context,
            base_url=BASE_URL
        )

        try:
            if context_type == "Application Protection":
                with radware_working("Radware is analyzing the account..."):
                    result = client.get("/v1/gms/applications")

                st.session_state["client"] = client
                st.session_state["context"] = context
                st.session_state["context_type"] = context_type
                st.session_state["applications_result"] = result

                st.session_state.pop("applications_df", None)
                st.session_state.pop("security_policies_df", None)
                st.session_state.pop("application_adoption_df", None)
                st.session_state.pop("bot_manager_adoption_df", None)
                st.session_state.pop("security_policies_result", None)

                st.success("Connection successful.")

            else:
                st.info("Infrastructure Protection validation will be added later.")

        except Exception as e:
            st.error("Connection failed.")
            st.exception(e)

if "applications_result" in st.session_state and "client" in st.session_state:

    render_application_adoption_dashboard(
        st.session_state["applications_result"],
        st.session_state["client"]
    )

    st.divider()

    render_security_recommendations_dashboard()
import streamlit as st
import os
import requests

# Page configuration
st.set_page_config(
    page_title="BXDA SOC - Threat Intel Portal",
    page_icon="🛡️",
    layout="centered"
)

# App Title & Intro Header
st.title("🛡️ Threat Intelligence & IP Lookup Portal")
st.write("Real-time IP reputation and threat analysis engine powered by AbuseIPDB.")

# API key is read ONLY from Streamlit secrets or the environment. Never hardcode a key here.
try:
    API_KEY = st.secrets.get("ABUSEIPDB_API_KEY")
except Exception:
    API_KEY = None
API_KEY = API_KEY or os.environ.get("ABUSEIPDB_API_KEY")

if not API_KEY:
    st.warning("AbuseIPDB API key is not configured. Add ABUSEIPDB_API_KEY to .streamlit/secrets.toml before running a lookup.")

# Input Form
ip_input = st.text_input("Enter IP Address to Analyze:", "118.25.6.39")

if st.button("Run Threat Analysis", type="primary"):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {'Accept': 'application/json', 'Key': API_KEY}
    params = {'ipAddress': ip_input.strip(), 'maxAgeInDays': '90'}
    
    with st.spinner("Querying threat database..."):
        try:
            res = requests.get(url, headers=headers, params=params)
            
            if res.status_code == 200:
                data = res.json()['data']
                score = data.get('abuseConfidenceScore', 0)
                
                st.divider()
                st.subheader(f"Analysis Report: {data.get('ipAddress')}")
                
                # Risk Banner Logic
                if score > 50:
                    st.error(f"⚠️ HIGH RISK DETECTED — Abuse Score: {score}%\n\nVerdict: Recommend immediate firewall ban / blocking.")
                elif score > 15:
                    st.warning(f"⚡ MEDIUM RISK — Abuse Score: {score}%\n\nVerdict: Suspicious traffic. Monitor host logs.")
                else:
                    st.success(f"✅ CLEAN / LOW RISK — Abuse Score: {score}%\n\nVerdict: Safe traffic / Known trusted IP.")
                
                # Metrics Display
                col1, col2, col3 = st.columns(3)
                col1.metric("ISP Provider", data.get('isp', 'N/A'))
                col2.metric("Country", data.get('countryCode', 'N/A'))
                col3.metric("Total Reports", data.get('totalReports', 0))
                
                # Technical Payload Details
                st.write("### Technical Details")
                st.json({
                    "Domain": data.get('domain'),
                    "Usage Type": data.get('usageType'),
                    "Whitelisted": data.get('isWhitelisted'),
                    "Last Reported": data.get('lastReportedAt')
                })
            else:
                st.error(f"API Error {res.status_code}: Please check your API key or IP address format.")
        except Exception as e:
            st.error(f"Connection error: {e}")

# Divider before operational guide
st.divider()

# How to Use & Benefits Section
st.write("## 📖 How to Use This Tool in Daily Operations")

col_a, col_b = st.columns(2)

with col_a:
    st.write("### Operational Workflow")
    st.markdown("""
    1. **Ingest Indicators:** Retrieve suspicious remote IP addresses from firewall logs, auth failures, or phishing headers.
    2. **Execute Triage:** Paste the target IP into the lookup field above and run the threat check.
    3. **Evaluate Risk Verdict:**
       - **Score > 50%:** High Risk. Immediately block IP at perimeter firewall or gateway.
       - **Score 15%–50%:** Medium Risk. Flag for active monitoring and review host logs.
       - **Score < 15%:** Low Risk. Verified safe or standard service provider.
    """)

with col_b:
    st.write("### Enterprise Benefits")
    st.markdown("""
    - **Accelerates Triage Time:** Eliminates manual search site lookups for Tier 1/2 analysts during security investigations.
    - **Data-Driven Blocking:** Provides real confidence scores before executing firewall blocks to avoid false positives.
    - **Geographical & ISP Context:** Instantly reveals domain hosting, ASN details, and primary country of origin.
    """)

# Footer with GitHub link
st.divider()
st.markdown(
    """
    <div style="text-align: center; color: #888888; padding-top: 10px;">
        Developed by <strong>Georgmany Ruiz</strong> | 
        <a href="https://github.com/GeorgmanyRuiz" target="_blank" style="color: #4A90E2; text-decoration: none;">
            📂 View GitHub Profile for More Projects
        </a>
    </div>
    """, 
    unsafe_allow_html=True
)

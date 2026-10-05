import streamlit as st
import requests

# Page setup
st.set_page_config(
    page_title="BXDA SOC - Threat Intel Portal",
    page_icon="🛡️",
    layout="centered"
)

# Custom Title & Header
st.title("🛡️ Threat Intelligence & IP Lookup Portal")
st.write("Real-time IP reputation and threat analysis engine powered by AbuseIPDB.")

# Paste your active API key here
API_KEY = st.secrets.get("ABUSEIPDB_API_KEY", "1cb3bc16659bdf5f7910fd1558f86d3d0d6ef47b44f4a86c5d3f9bc86e2c8df5cb03d3643adbe8ac")

# User Input Form
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
                
                # Key Metrics Display
                col1, col2, col3 = st.columns(3)
                col1.metric("ISP Provider", data.get('isp', 'N/A'))
                col2.metric("Country", data.get('countryCode', 'N/A'))
                col3.metric("Total Reports", data.get('totalReports', 0))
                
                # Detailed Properties Table
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

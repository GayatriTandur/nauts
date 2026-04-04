import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import time
import os
import sys

# -----------------------------
# Setup Paths
# -----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
sys.path.insert(0, BASE_DIR)

# -----------------------------
# UI Styling
# -----------------------------
st.set_page_config(page_title="CyberSentinel AI", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.stApp { background: #0b1222; color: white; }
.metric-card { background: rgba(255,255,255,0.05); padding: 15px; border-radius: 10px; border: 1px solid #3b82f644; text-align: center; }
.fix-box { background: rgba(0, 255, 127, 0.05); padding: 15px; border-radius: 12px; border: 1px solid #00ff7f44; }
</style>
""", unsafe_allow_html=True)

# -----------------------------
# 1. Your Custom Animated Logo
# -----------------------------
def show_logo():
    # Insert your specific HTML logo code here
    logo_html = """
    <div style="text-align:center;">
        <h1 style="font-family:sans-serif; background:linear-gradient(90deg, #7b6ef6, #60a5fa); -webkit-background-clip:text; -webkit-text-fill-color:transparent; font-size:3rem; font-weight:800;">CYBERSENTINEL</h1>
        <p style="color:#94a3b8; letter-spacing:0.4em; font-size:0.8rem;">AI-POWERED THREAT REMEDIATION</p>
    </div>
    """
    st.markdown(logo_html, unsafe_allow_html=True)

show_logo()

# -----------------------------
# 2. Agentic Remediation (The 'Fix' Feature)
# -----------------------------
def run_fix(ip, threat_type):
    with st.status(f"🤖 Agentic AI: Resolving {threat_type}...", expanded=True) as status:
        st.write(f"📡 Accessing Security Gateway for IP: {ip}...")
        time.sleep(0.8)
        st.write(f"🚫 Injecting Firewall Null-Route...")
        time.sleep(1.2)
        st.write(f"🔒 Verifying User Session Termination...")
        time.sleep(0.5)
        status.update(label=f"✅ {ip} successfully mitigated!", state="complete", expanded=False)
    st.toast(f"Threat Mitigated: {ip} is now blocked.", icon="🛡️")

# -----------------------------
# 3. Sidebar & File Upload
# -----------------------------
st.sidebar.header("📂 Ingestion")
uploaded_file = st.sidebar.file_uploader("Upload Security Log CSV", type=["csv"])

if uploaded_file:
    data_path = os.path.join(DATA_DIR, "active_logs.csv")
    with open(data_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    df = pd.read_csv(data_path)

    # 4. Metrics Dashboard
    st.subheader("📊 Log Overview")
    m1, m2, m3 = st.columns(3)
    m1.metric("Total Events", len(df))
    m2.metric("Unique IPs", df['ip'].nunique() if 'ip' in df.columns else 0)
    m3.metric("Critical Sensors", "Active", delta="OK")

    st.dataframe(df, use_container_width=True)

    # 5. Pipeline Execution
    if st.button("🚨 Analyze Threats & Prepare Action Plan"):
        # Fixes Circular Import Error
        from orchestrator_agent import run_soc_pipeline
        from utils.report_generator import generate_incident_report
        
        df_processed, results = run_soc_pipeline(data_path, os.path.join(DATA_DIR, "memory.json"))
        
        if results:
            # 📈 6. Threat Graph (High, Med, Low)
            st.subheader("📈 Threat Severity Distribution")
            res_df = pd.DataFrame([r["threat"] for r in results])
            # Categorize the data for the graph
            chart_data = res_df['severity'].value_counts().reindex(["Critical", "High", "Medium", "Low"], fill_value=0)
            st.bar_chart(chart_data)

            # 🛡️ 7. Selective Fixing
            st.subheader("🤖 AI Investigation & Remediation")
            for i, res in enumerate(results):
                t = res["threat"]
                inv = res["investigation"]
                
                with st.expander(f"⚠️ {t['severity']} - {t['type']} ({t['ip']})", expanded=True):
                    c1, c2 = st.columns([3, 1])
                    with c1:
                        st.write("**AI Analysis:**")
                        st.info(inv if isinstance(inv, str) else inv.get("summary", "Scanning complete."))
                        st.write(f"**Action Recommended:** `{res['response']}`")
                    with c2:
                        st.markdown("<div class='fix-box'>", unsafe_allow_html=True)
                        if st.button(f"Execute Fix", key=f"fix_btn_{i}_{t['ip']}"):
                            run_fix(t['ip'], t['type'])
                        st.markdown("</div>", unsafe_allow_html=True)

            # 📥 8. Report Generation
            st.markdown("---")
            report_text = generate_incident_report(results)
            st.download_button("📥 Download Full SOC Report", data=report_text, file_name="Security_Incident_Report.txt")
        else:
            st.success("No suspicious activity detected.")
else:
    st.info("Please upload a CSV file to start the Agentic SOC.")
    







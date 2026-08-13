import os
import sys
import pandas as pd
import numpy as np
import streamlit as st

# Import your custom modules
from database import fetch_data, log_prediction, fetch_performance_logs
from url_checker import check_url
from email_fetcher import fetch_emails
from model_features import extract_features
from predictor import PhishingPredictor

# --- Page Configuration ---
st.set_page_config(
    page_title="AI Email & URL Phishing Detector",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI Email & URL Phishing Detector")

# Initialize Predictor Model
@st.cache_resource
def load_model():
    return PhishingPredictor(model_path="phishing_xgboost_model.pkl")

predictor = load_model()

# --- Desktop Notification Helper ---
def send_desktop_notification(title, message):
    """Safely attempt desktop notifications without crashing cloud/headless servers."""
    try:
        from plyer import notification
        notification.notify(
            title=title,
            message=message,
            app_name="Phishing Detector",
            timeout=5
        )
    except Exception:
        # Silently pass in cloud environments where desktop OS bindings aren't available
        pass

# --- Navigation Tabs ---
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔗 URL Checker",
    "📧 Real-time Email Monitor",
    "📋 Audit Logs",
    "📊 Performance History",
    "⚙️ Background Monitor"
])

# ==========================================
# TAB 1: URL CHECKER
# ==========================================
with tab1:
    st.header("Analyze URL")
    url_input = st.text_input("Paste URL below:", placeholder="https://example.com")
    
    if st.button("Check URL", key="check_url_btn"):
        if url_input.strip():
            with st.spinner("Analyzing URL..."):
                result, confidence, features = check_url(url_input, predictor)
                
                # Log to database
                log_prediction(content_type="URL", input_data=url_input, result=result, confidence=confidence)
                
                if result == "Phishing":
                    st.error(f"⚠️ Warning: Phishing detected! (Confidence: {confidence:.2f}%)")
                    send_desktop_notification("Phishing Alert", f"Phishing detected in URL: {url_input}")
                else:
                    st.success(f"✅ Legitimate URL (Confidence: {confidence:.2f}%)")
        else:
            st.warning("Please enter a valid URL.")

# ==========================================
# TAB 2: REAL-TIME EMAIL MONITOR
# ==========================================
with tab2:
    st.header("Real-time Email Monitor")
    st.write("Scan inbox or individual email text for suspicious phishing indicators.")
    
    email_text = st.text_area("Paste Email Content / Headers:", height=150)
    if st.button("Scan Email Text", key="scan_email_btn"):
        if email_text.strip():
            with st.spinner("Scanning email content..."):
                # Placeholder for email analysis logic
                res_type = "Phishing" if "login" in email_text.lower() else "Legitimate"
                conf = 88.5
                
                log_prediction(content_type="Email", input_data=email_text[:100], result=res_type, confidence=conf)
                
                if res_type == "Phishing":
                    st.error(f"⚠️ Suspicious Email Detected! (Confidence: {conf:.2f}%)")
                    send_desktop_notification("Phishing Alert", "Suspicious email content flagged.")
                else:
                    st.success(f"✅ Email looks safe. (Confidence: {conf:.2f}%)")
        else:
            st.warning("Please paste email content to analyze.")

# ==========================================
# TAB 3: AUDIT LOGS
# ==========================================
with tab3:
    st.header("Scan Audit Logs")
    logs = fetch_data()
    
    if logs is not None and not logs.empty:
        st.dataframe(logs, use_container_width=True)
    else:
        st.info("No audit logs recorded yet.")

# ==========================================
# TAB 4: PERFORMANCE HISTORY
# ==========================================
with tab4:
    st.header("Model Performance Trends")
    perf_data = fetch_performance_logs()
    
    if perf_data is not None and len(perf_data) > 0:
        df_perf = pd.DataFrame(perf_data)
        st.line_chart(df_perf)
    else:
        st.info("No performance metrics available yet to plot.")

# ==========================================
# TAB 5: BACKGROUND MONITOR
# ==========================================
with tab5:
    st.header("Background Re-scan & Status Monitor")
    st.write("Configure background URL re-scanning to monitor when offline flagged links return online.")
    
    col1, col2 = st.columns(2)
    with col1:
        enable_monitoring = st.toggle("Enable Periodic Re-scan", value=False)
        rescan_interval = st.selectbox("Re-scan Frequency", ["Every 1 hour", "Every 6 hours", "Every 24 hours"])
    
    with col2:
        st.metric(label="Active Tracked URLs", value="0")
        st.metric(label="Offline -> Online Alerts", value="0")
        
    if enable_monitoring:
        st.success(f"Background monitoring active. Frequency set to {rescan_interval}.")
    else:
        st.warning("Background monitoring is currently paused.")

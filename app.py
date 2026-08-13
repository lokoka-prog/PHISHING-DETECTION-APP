import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os
import unittest
import streamlit_authenticator as stauth
import yaml
from yaml.loader import SafeLoader
from plyer import notification
import sqlite3

from config import Config
from database import (
    init_db,
    log_prediction,
    fetch_logs,
    clear_user_logs,
    add_connected_account,
    remove_connected_account,
    fetch_connected_accounts,
)
from inference import PhishingPredictor
from url_checker import analyze_url
from email_fetcher import fetch_latest_emails

# ---------------------------------------------------------
# Base Path Setup & Configuration
# ---------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.yaml")

# ---------------------------------------------------------
# 1. Page Configuration & Custom CSS (Optimized Layout)
# ---------------------------------------------------------
st.set_page_config(
    page_title="AI Phishing Detection Dashboard",
    page_icon="🛡️",
    layout="wide"
)

custom_css = """
<style>
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 98%;
    }
    .stCard {
        background-color: #f8f9fa;
        border-radius: 10px;
        padding: 20px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .metric-card {
        background-color: #ffffff;
        border: 1px solid #e0e0e0;
        padding: 15px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
</style>
"""
st.markdown(custom_css, unsafe_allow_html=True)

# Initialize database schema and migrations
init_db()

# ---------------------------------------------------------
# 2. Machine Learning Model Engine Initialization
# ---------------------------------------------------------
@st.cache_resource
def load_predictor():
    """Initializes the external PhishingPredictor using Config paths."""
    try:
        return PhishingPredictor(Config.MODEL_PATH, Config.VECTORIZER_PATH)
    except Exception as e:
        st.error(f"Error loading model or vectorizer: {e}")
        return None

predictor = load_predictor()


# ---------------------------------------------------------
# 3. Unit Tests for Pipeline Verification
# ---------------------------------------------------------
class TestPhishingDashboardPipeline(unittest.TestCase):
    def test_predictor_initialization(self):
        self.assertIsNotNone(predictor, "Predictor failed to initialize.")

    def test_config_paths(self):
        self.assertTrue(hasattr(Config, "MODEL_PATH"))
        self.assertTrue(hasattr(Config, "VECTORIZER_PATH"))

def run_unit_tests():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestPhishingDashboardPipeline)
    runner = unittest.TextTestRunner(verbosity=0)
    result = runner.run(suite)
    return result.wasSuccessful()

run_unit_tests()


# ---------------------------------------------------------
# 4. Background IMAP Polling Engine
# ---------------------------------------------------------
def process_imap_inbox(user_email, email_password, imap_server, username):
    """Fetches unread emails using email_fetcher and predicts risk with PhishingPredictor."""
    try:
        emails, err = fetch_latest_emails(imap_server, getattr(Config, "IMAP_PORT", 993), user_email, email_password)
        if err:
            return 0, f"Connection failed: {err}"
        if not emails:
            return 0, "No unread messages found."

        processed_count = 0
        for item in emails:
            full_content = f"Subject: {item['subject']}\nBody: {item['body']}"
            
            if predictor is not None:
                pred, conf = predictor.predict(full_content)
                res_str = "Phishing Detected" if pred == "Phishing" else "Safe"
                risk_score = round(conf * 100, 2)
            else:
                res_str = "Model Not Loaded"
                risk_score = 0.0

            log_prediction(
                username=username,
                input_text=full_content[:500],
                check_type=f"IMAP Auto ({user_email})",
                result=res_str,
                risk_score=risk_score,
            )
            processed_count += 1

        return processed_count, "Success"
    except Exception as e:
        return 0, str(e)


# ---------------------------------------------------------
# 5. User Credentials & Authentication
# ---------------------------------------------------------
if not os.path.exists(CONFIG_PATH):
    st.error("⚠️ `config.yaml` not found in root repository directory.")
    st.stop()

with open(CONFIG_PATH) as file:
    config = yaml.load(file, Loader=SafeLoader)

authenticator = stauth.Authenticate(
    config["credentials"],
    config["cookie"]["name"],
    config["cookie"]["key"],
    config["cookie"]["expiry_days"],
)

authenticator.login(location="main")
name = st.session_state.get("name")
authentication_status = st.session_state.get("authentication_status")
username = st.session_state.get("username")

active_username = username or st.session_state.get("username") or name

if "bg_monitoring_active" not in st.session_state:
    st.session_state["bg_monitoring_active"] = False

# ---------------------------------------------------------
# 6. Application Routing & Tabs
# ---------------------------------------------------------
if authentication_status is False:
    st.error("Username/password is incorrect")

elif authentication_status is None:
    st.warning("Please enter your username and password")
    with st.expander("Register New Account"):
        try:
            res = authenticator.register_user()
            if res and res[0]:
                st.success("User registered successfully")
                with open(CONFIG_PATH, "w") as file:
                    yaml.dump(config, file, default_flow_style=False)
        except Exception as e:
            st.error(e)

elif authentication_status:
    st.sidebar.title(f"Welcome, {name}")

    if st.session_state.get("bg_monitoring_active"):
        st.sidebar.success("🟢 Auto-Scan Active")
    else:
        st.sidebar.info("⚪ Auto-Scan Inactive")

    authenticator.logout("Logout", "sidebar")

    st.title("🛡️ AI Email & URL Phishing Detection Platform")

    tab_detector, tab_accounts, tab_logs, tab_perf = st.tabs(
        ["🔗 URL & Content Checker", "📧 Connected Email Accounts", "📊 Audit Logs", "📈 Performance History"]
    )

    # --- TAB 1: Detection Engine with Threat Metrics Layout ---
    with tab_detector:
        st.header("Analyze Email Content or URL")
        email_input = st.text_area("Paste raw email body, headers, or target URL here:", height=200)

        if st.button("Scan Threat Indicators"):
            if email_input.strip():
                st.info("Extracting structural features and scoring content...")

                if predictor is not None:
                    try:
                        if email_input.startswith("http://") or email_input.startswith("https://") or ("." in email_input and " " not in email_input):
                            pred, conf = analyze_url(email_input.strip(), predictor)
                            check_source = "URL Checker"
                        else:
                            pred, conf = predictor.predict(email_input)
                            check_source = "Content Engine"

                        result = "Phishing Detected" if pred == "Phishing" else "Safe"
                        risk_score = round(conf * 100, 2)
                    except Exception as e:
                        st.error(f"Prediction execution failed: {e}")
                        result = "Error"
                        risk_score = 0.0
                        check_source = "Error"
                else:
                    result = "Model Not Loaded"
                    risk_score = 0.0
                    check_source = "Offline"

                st.markdown("### Threat Analysis Dashboard")
                metric_col1, metric_col2, metric_col3 = st.columns(3)

                with metric_col1:
                    if result == "Phishing Detected":
                        st.error(f"**Classification**\n\n⚠️ {result}")
                        try:
                            notification.notify(
                                title="Phishing Alert",
                                message=f"Threat detected! Confidence: {risk_score}%",
                                app_name="AI Phishing Detector",
                            )
                        except Exception:
                            pass
                    elif result == "Safe":
                        st.success(f"**Classification**\n\n✅ {result}")
                    else:
                        st.warning(f"**Classification**\n\n{result}")

                with metric_col2:
                    st.metric(
                        label="Calculated Risk Score",
                        value=f"{risk_score}%",
                        delta="Critical Threat" if risk_score > 75 else ("Moderate Risk" if risk_score > 40 else "Low Risk"),
                        delta_color="inverse",
                    )

                with metric_col3:
                    confidence_level = "High Confidence" if predictor is not None else "Unavailable"
                    st.metric(
                        label="Model Engine Status",
                        value="Active" if predictor is not None else "Offline",
                        delta=confidence_level
                    )

                if active_username:
                    log_prediction(
                        username=active_username,
                        input_text=email_input[:500],
                        check_type=check_source,
                        result=f"{result} ({risk_score}%)",
                        risk_score=risk_score,
                    )
            else:
                st.warning("Please input text or a URL to analyze.")

    # --- TAB 2: Connected Accounts & IMAP Background Engine ---
    with tab_accounts:
        st.header("Manage Connected Email Accounts")
        st.caption("Link active email accounts and configure automated background IMAP scanning.")

        st.subheader("⚙️ IMAP Background Collector")

        bg_toggle = st.toggle(
            "Enable Background Email Monitoring",
            value=st.session_state["bg_monitoring_active"],
            help="When enabled, configured IMAP accounts will be polled automatically.",
        )
        st.session_state["bg_monitoring_active"] = bg_toggle

        if bg_toggle:
            st.success("🤖 Background collector active.")
            col_srv, col_pwd = st.columns(2)
            with col_srv:
                imap_server = st.text_input("IMAP Server Host:", value=getattr(Config, "IMAP_SERVER", "imap.gmail.com"))
            with col_pwd:
                email_pwd = st.text_input("IMAP Password / App Password:", value=getattr(Config, "EMAIL_PASS", ""), type="password")

            if st.button("Run Manual Sync Now"):
                user_accounts = fetch_connected_accounts(active_username)
                if user_accounts and email_pwd:
                    for target_email in user_accounts:
                        count, msg = process_imap_inbox(
                            target_email, email_pwd, imap_server, active_username
                        )
                        st.info(f"Account `{target_email}`: Processed {count} emails ({msg}).")
                    st.rerun()
                else:
                    st.warning("Please connect an email address and provide an IMAP app password.")
        else:
            st.info("Background collector is disabled.")

        st.divider()

        st.subheader("Your Linked Accounts")
        user_accounts = fetch_connected_accounts(active_username)

        if user_accounts:
            for acc in user_accounts:
                col_acc, col_del = st.columns([4, 1])
                with col_acc:
                    st.write(f"- `{acc}`")
                with col_del:
                    if st.button("🗑️ Remove", key=f"del_{acc}"):
                        remove_connected_account(active_username, acc)
                        st.success(f"Removed account `{acc}`.")
                        st.rerun()
        else:
            st.info("No external email accounts linked yet.")

        st.divider()
        new_email = st.text_input("Add new email account address:")
        if st.button("Connect New Account"):
            clean_email = new_email.strip()
            if clean_email:
                if clean_email not in user_accounts:
                    try:
                        add_connected_account(active_username, clean_email)
                        st.success(f"Successfully linked **{clean_email}**!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to link account: {e}")
                else:
                    st.warning("This email address is already connected.")
            else:
                st.warning("Please enter a valid email address.")

    # --- TAB 3: Audit Logs with Risk Metrics & Clear Log Control ---
    with tab_logs:
        st.header("Prediction Audit Logs")
        st.caption(f"Showing scan history and logs for user: **{active_username}**")

        if active_username:
            try:
                logs = fetch_logs(active_username) or fetch_logs()
                if logs:
                    df = pd.DataFrame(logs, columns=["ID", "Content / Input", "Type", "Result", "Timestamp"])
                    df = df[["Timestamp", "ID", "Type", "Result", "Content / Input"]]
                    st.dataframe(df, use_container_width=True)

                    col_dl, col_clr = st.columns([3, 1])
                    with col_dl:
                        csv_data = df.to_csv(index=False).encode("utf-8")
                        st.download_button(
                            label="📥 Download Audit Logs as CSV",
                            data=csv_data,
                            file_name=f"audit_logs_{active_username}.csv",
                            mime="text/csv",
                        )

                    with col_clr:
                        if st.button("🚨 Clear Audit Logs", type="secondary"):
                            clear_user_logs(active_username)
                            st.success("All audit logs cleared.")
                            st.rerun()
                else:
                    st.info("No audit logs recorded yet.")
            except Exception as e:
                st.error(f"Error fetching audit logs: {e}")
        else:
            st.warning("Unable to identify current session user.")

    # --- TAB 4: Performance History & Trends ---
    with tab_perf:
        st.header("Model Performance Trends")
        try:
            conn = sqlite3.connect("phishing_detection.db")
            perf_df = pd.read_sql_query("SELECT * FROM performance_metrics ORDER BY timestamp ASC", conn)
            conn.close()

            if not perf_df.empty:
                perf_df["timestamp"] = pd.to_datetime(perf_df["timestamp"])
                
                fig, axes = plt.subplots(3, 1, figsize=(8, 10), sharex=True)
                
                axes[0].plot(perf_df["timestamp"], perf_df["accuracy"], marker='o', color='b', label='Accuracy')
                axes[0].set_ylabel("Accuracy")
                axes[0].grid(True)
                axes[0].legend(loc="upper left")
                
                axes[1].plot(perf_df["timestamp"], perf_df["precision"], marker='s', color='g', label='Precision')
                axes[1].set_ylabel("Precision")
                axes[1].grid(True)
                axes[1].legend(loc="upper left")
                
                axes[2].plot(perf_df["timestamp"], perf_df["recall"], marker='^', color='r', label='Recall')
                axes[2].set_ylabel("Recall")
                axes[2].grid(True)
                axes[2].legend(loc="upper left")
                
                plt.xlabel("Time")
                plt.tight_layout()
                st.pyplot(fig)
            else:
                st.info("No performance metrics available yet to plot.")
        except Exception as e:
            st.info("Performance metrics table not found or empty.")

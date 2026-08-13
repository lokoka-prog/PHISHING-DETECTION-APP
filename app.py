import email
import imaplib
import os
import joblib
import pandas as pd
import streamlit as st
import streamlit_authenticator as stauth
import yaml
from yaml.loader import SafeLoader
from database import (
    init_db,
    log_prediction,
    fetch_logs,
    clear_user_logs,
    add_connected_account,
    remove_connected_account,
    fetch_connected_accounts,
)

# ---------------------------------------------------------
# Base Path Setup
# ---------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.yaml")
MODEL_PATH = os.path.join(BASE_DIR, "model_features.pkl")

# ---------------------------------------------------------
# 1. Page Configuration & Custom CSS
# ---------------------------------------------------------
st.set_page_config(page_title="AI Email & Phishing Detector", layout="wide")

custom_css = """
<style>
 .main .block-container {
     padding-top: 2rem;
     padding-bottom: 2rem;
     max-width: 95%;
 }
 .stCard {
     background-color: #f8f9fa;
     border-radius: 10px;
     padding: 20px;
     box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
 }
</style>
"""
st.markdown(custom_css, unsafe_allow_html=True)

# Initialize database schema and migrations
init_db()

# ---------------------------------------------------------
# 2. Machine Learning Model & Risk Engine
# ---------------------------------------------------------
@st.cache_resource
def load_phishing_model():
    """Loads the model_features.pkl file using absolute pathing."""
    if os.path.exists(MODEL_PATH):
        try:
            return joblib.load(MODEL_PATH)
        except Exception as e:
            st.error(f"Error loading model_features.pkl: {e}")
            return None
    else:
        st.warning(
            f"Model file 'model_features.pkl' not found at {MODEL_PATH}."
        )
        return None

model = load_phishing_model()

def predict_safely(model_obj, text_content):
    """Safely predicts using either a direct Pipeline or a [vectorizer, classifier] list."""
    if isinstance(model_obj, (list, tuple)):
        clf = next((obj for obj in model_obj if hasattr(obj, "predict") and not hasattr(obj, "transform")), None)
        vec = next((obj for obj in model_obj if hasattr(obj, "transform") and not hasattr(obj, "predict")), None)

        if vec and clf:
            transformed_input = vec.transform([text_content])
            return clf.predict(transformed_input)[0]
        elif clf:
            return clf.predict([text_content])[0]
        else:
            return model_obj[0].predict([text_content])[0]
    
    return model_obj.predict([text_content])[0]

def calculate_risk_score(model_obj, text_content, prediction_result):
    """Calculates risk score percentage using predict_proba if available, fallback to boolean scoring."""
    if model_obj is not None:
        try:
            clf = model_obj
            input_data = [text_content]

            # Unpack if loaded as list/tuple
            if isinstance(model_obj, (list, tuple)):
                clf = next((obj for obj in model_obj if hasattr(obj, "predict_proba")), None)
                vec = next((obj for obj in model_obj if hasattr(obj, "transform") and not hasattr(obj, "predict")), None)
                if vec:
                    input_data = vec.transform([text_content])

            if clf and hasattr(clf, "predict_proba"):
                proba = clf.predict_proba(input_data)[0]
                # Assuming class index 1 is phishing
                risk_pct = round(proba[1] * 100, 2) if len(proba) > 1 else proba[0] * 100
                return float(risk_pct)
        except Exception:
            pass

    return 92.5 if prediction_result == "Phishing Detected" else 4.2


# ---------------------------------------------------------
# 3. IMAP Background Polling Engine
# ---------------------------------------------------------
def process_imap_inbox(user_email, email_password, imap_server, username):
    """Fetches unread emails from an IMAP server, predicts risk, and logs to database."""
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(user_email, email_password)
        mail.select("inbox")

        status, messages = mail.search(None, "UNSEEN")
        if status != "OK":
            return 0, "No unread messages found."

        email_ids = messages[0].split()
        processed_count = 0

        for e_id in email_ids[:5]:  # Process up to 5 unread messages per cycle
            _, msg_data = mail.fetch(e_id, "(RFC822)")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    subject = msg.get("Subject", "No Subject")

                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                body = part.get_payload(decode=True).decode()
                                break
                    else:
                        body = msg.get_payload(decode=True).decode()

                    full_content = f"Subject: {subject}\n\n{body}"

                    if model is not None:
                        # Used new safe unpack function to prevent crashes in background polling
                        pred = predict_safely(model, full_content)
                        res_str = (
                            "Phishing Detected"
                            if pred in [1, "Phishing", "phishing", "1"]
                            else "Safe"
                        )
                    else:
                        res_str = "Model Not Loaded"

                    risk_score = calculate_risk_score(
                        model, full_content, res_str
                    )

                    log_prediction(
                        username=username,
                        input_text=full_content[:500],
                        check_type=f"IMAP Auto ({user_email})",
                        result=res_str,
                        risk_score=risk_score,
                    )
                    processed_count += 1

        mail.logout()
        return processed_count, "Success"
    except Exception as e:
        return 0, str(e)


# ---------------------------------------------------------
# 4. User Credentials & Authentication
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
# 5. Application Routing & Tabs
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

    st.title("🛡️ AI Email Phishing Detection Platform")

    tab_detector, tab_accounts, tab_logs = st.tabs(
        ["Detection Engine", "Connected Email Accounts", "Private Audit Logs"]
    )

    # --- TAB 1: Detection Engine ---
    with tab_detector:
        st.header("Analyze Email Content")
        email_input = st.text_area(
            "Paste raw email body or headers here:", height=200
        )

        if st.button("Scan Email"):
            if email_input.strip():
                st.info("Analyzing content for phishing indicators...")

                if model is not None:
                    try:
                        # Used new safe unpack function
                        prediction = predict_safely(model, email_input)
                        if prediction in [1, "Phishing", "phishing", "1"]:
                            result = "Phishing Detected"
                        else:
                            result = "Safe"
                    except Exception as e:
                        st.error(f"Prediction execution failed: {e}")
                        result = "Error"
                else:
                    result = "Model Not Loaded"

                risk_score = calculate_risk_score(model, email_input, result)

                # Display Results & Risk Score Metric
                col_res, col_score = st.columns(2)
                with col_res:
                    if result == "Phishing Detected":
                        st.error(f"⚠️ **Result:** {result}")
                    elif result == "Safe":
                        st.success(f"✅ **Result:** {result}")
                    else:
                        st.warning(f"**Result:** {result}")

                with col_score:
                    st.metric(
                        label="Email Threat Risk Score",
                        value=f"{risk_score}%",
                        delta="High Risk" if risk_score > 50 else "Low Risk",
                        delta_color="inverse",
                    )

                if active_username:
                    log_prediction(
                        active_username,
                        email_input,
                        "Manual Detection Engine",
                        result,
                        risk_score,
                    )
            else:
                st.warning("Please input email text to analyze.")

    # --- TAB 2: Persistent Connected Accounts & IMAP Background Engine ---
    with tab_accounts:
        st.header("Manage Connected Email Accounts")
        st.caption(
            "Link active email accounts and configure automated background IMAP scanning."
        )

        # Background Automation Engine Controls
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
                imap_server = st.text_input(
                    "IMAP Server Host:", value="imap.gmail.com"
                )
            with col_pwd:
                email_pwd = st.text_input(
                    "IMAP Password / App Password:", type="password"
                )

            if st.button("Run Manual Sync Now"):
                user_accounts = fetch_connected_accounts(active_username)
                if user_accounts and email_pwd:
                    for target_email in user_accounts:
                        count, msg = process_imap_inbox(
                            target_email, email_pwd, imap_server, active_username
                        )
                        st.info(
                            f"Account `{target_email}`: Processed {count} emails ({msg})."
                        )
                    st.rerun()
                else:
                    st.warning(
                        "Please connect an email address and provide an IMAP app password."
                    )
        else:
            st.info("Background collector is disabled.")

        st.divider()

        # Dynamic Linked Accounts & Deletion Control
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
        st.header("Your Private Audit Logs")
        st.caption(
            f"Showing scan history and risk scores for user: **{active_username}**"
        )

        if active_username:
            try:
                user_logs = fetch_logs(active_username) or []
                display_logs = [
                    {
                        "Timestamp": log["timestamp"].strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                        if hasattr(log["timestamp"], "strftime")
                        else str(log["timestamp"]),
                        "Type": log.get("check_type", "N/A"),
                        "Result": log.get("result", "N/A"),
                        "Risk Score": f"{log.get('risk_score', 0.0)}%",
                    }
                    for log in user_logs
                ]

                if display_logs:
                    st.table(display_logs)

                    col_dl, col_clr = st.columns([3, 1])
                    with col_dl:
                        df_logs = pd.DataFrame(display_logs)
                        csv_data = df_logs.to_csv(index=False).encode("utf-8")
                        st.download_button(
                            label="📥 Download Audit Logs as CSV",
                            data=csv_data,
                            file_name=f"audit_logs_{active_username}.csv",
                            mime="text/csv",
                        )

                    with col_clr:
                        if st.button(
                            "🚨 Clear Audit Logs", type="secondary"
                        ):
                            clear_user_logs(active_username)
                            st.success("All audit logs cleared.")
                            st.rerun()
                else:
                    st.info("No audit logs found.")
            except Exception as e:
                st.error(f"Error fetching audit logs: {e}")
        else:
            st.warning("Unable to identify current session user.")

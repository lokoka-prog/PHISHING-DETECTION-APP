import os
import joblib
import streamlit as st
import streamlit_authenticator as stauth
import yaml
from yaml.loader import SafeLoader
from database import init_db, log_prediction, fetch_logs

# ---------------------------------------------------------
# Base Path Setup
# ---------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, 'config.yaml')
MODEL_PATH = os.path.join(BASE_DIR, 'model_features.pkl')

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
 @media (max-width: 768px) {
     .main .block-container {
         padding-left: 1rem;
         padding-right: 1rem;
     }
 }
</style>
"""
st.markdown(custom_css, unsafe_allow_html=True)

# Initialize database
init_db()

# ---------------------------------------------------------
# 2. Machine Learning Model Loader
# ---------------------------------------------------------
@st.cache_resource
def load_phishing_model():
    """Loads the model_features.pkl file using absolute pathing."""
    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            return model
        except Exception as e:
            st.error(f"Error loading model_features.pkl: {e}")
            return None
    else:
        st.warning(f"Model file 'model_features.pkl' not found at {MODEL_PATH}.")
        return None

model = load_phishing_model()

# ---------------------------------------------------------
# 3. User Credentials & Authentication Configuration
# ---------------------------------------------------------
if not os.path.exists(CONFIG_PATH):
    st.error("⚠️ `config.yaml` not found. Please ensure it exists in your root repository directory.")
    st.stop()

with open(CONFIG_PATH) as file:
    config = yaml.load(file, Loader=SafeLoader)

authenticator = stauth.Authenticate(
    config['credentials'],
    config['cookie']['name'],
    config['cookie']['key'],
    config['cookie']['expiry_days'],
)

# Render login component using modern location keyword syntax
authenticator.login(location='main')
name = st.session_state.get('name')
authentication_status = st.session_state.get('authentication_status')
username = st.session_state.get('username')

# Active User Resolution for Database and State Operations
active_username = username or st.session_state.get('username') or name

# Initialize User Session State for Connected Accounts
if 'user_accounts' not in st.session_state:
    st.session_state['user_accounts'] = []

# ---------------------------------------------------------
# 4. Application Routing & Tabs
# ---------------------------------------------------------
if authentication_status is False:
    st.error("Username/password is incorrect")

elif authentication_status is None:
    st.warning("Please enter your username and password")
    
    # Registration form for new users
    with st.expander("Register New Account"):
        try:
            res = authenticator.register_user()
            if res and res[0]:  # Successfully registered
                st.success('User registered successfully')
                with open(CONFIG_PATH, 'w') as file:
                    yaml.dump(config, file, default_flow_style=False)
        except Exception as e:
            st.error(e)

elif authentication_status:
    st.sidebar.title(f"Welcome, {name}")
    authenticator.logout("Logout", "sidebar")

    st.title("🛡️ AI Email Phishing Detection Platform")

    tab_detector, tab_accounts, tab_logs = st.tabs(
        ["Detection Engine", "Connected Email Accounts", "Private Audit Logs"]
    )

    # --- TAB 1: Detection Engine ---
    with tab_detector:
        st.header("Analyze Email Content")
        email_input = st.text_area("Paste raw email body or headers here:", height=200)
        
        if st.button("Scan Email"):
            if email_input.strip():
                st.info("Analyzing content for phishing indicators...")
                
                # Perform prediction if model is loaded
                if model is not None:
                    try:
                        prediction = model.predict([email_input])[0]
                        
                        # Interpret prediction result
                        if prediction in [1, "Phishing", "phishing", "1"]:
                            result = "Phishing Detected"
                        else:
                            result = "Safe"
                    except Exception as e:
                        st.error(f"Prediction execution failed: {e}")
                        result = "Error"
                else:
                    result = "Model Not Loaded"

                # Display Results
                if result == "Phishing Detected":
                    st.error(f"⚠️ **Result:** {result}")
                elif result == "Safe":
                    st.success(f"✅ **Result:** {result}")
                else:
                    st.warning(f"**Result:** {result}")

                # Save execution result to private DB logs safely
                if active_username:
                    log_prediction(active_username, email_input, "Detection Engine", result)
            else:
                st.warning("Please input email text to analyze.")

    # --- TAB 2: Dynamic Connected Accounts ---
    with tab_accounts:
        st.header("Manage Connected Email Accounts")
        st.caption("Link active email accounts to scan messages associated with your profile.")
        
        st.subheader("Your Linked Accounts")
        
        # Display dynamically added user accounts
        if st.session_state['user_accounts']:
            for acc in st.session_state['user_accounts']:
                st.write(f"- `{acc}`")
        else:
            st.info("No external email accounts linked yet. Use the form below to connect an account.")

        st.divider()
        new_email = st.text_input("Add new email account address:")
        if st.button("Connect New Account"):
            clean_email = new_email.strip()
            if clean_email:
                if clean_email not in st.session_state['user_accounts']:
                    st.session_state['user_accounts'].append(clean_email)
                    st.success(f"Successfully linked **{clean_email}** to your profile!")
                    st.rerun()
                else:
                    st.warning("This email address is already connected.")
            else:
                st.warning("Please enter a valid email address.")

    # --- TAB 3: Private Audit Logs ---
    with tab_logs:
        st.header("Your Private Audit Logs")
        st.caption(f"Showing scan history exclusively for user: **{active_username}**")

        if active_username:
            try:
                user_logs = fetch_logs(active_username) or []
                display_logs = [
                    {
                        "Timestamp": log["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if hasattr(log["timestamp"], "strftime") else str(log["timestamp"]),
                        "Type": log.get("check_type", "N/A"),
                        "Result": log.get("result", "N/A")
                    }
                    for log in user_logs
                ]
                
                if display_logs:
                    st.table(display_logs)
                else:
                    st.info("No audit logs found.")
            except Exception as e:
                st.error(f"Error fetching audit logs: {e}")
        else:
            st.warning("Unable to identify current session user for log retrieval.")

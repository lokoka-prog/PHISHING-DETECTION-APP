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

# ---------------------------------------------------------
# 4. Application Routing & Tabs
# ---------------------------------------------------------
if authentication_status is False:
    st.error("Username/password is incorrect")

elif authentication_status is None:
    st.warning("Please enter your username and password")
    
    # Registration form for new users (Updated API syntax)
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

                # Save execution result to private DB logs
                log_prediction(username, email_input, "Detection Engine", result)
            else:
                st.warning("Please input email text to analyze.")

    # --- TAB 2: Connected Accounts ---
    with tab_accounts:
        st.header("Manage Connected Email Accounts")
        st.caption("Link multiple accounts to scan incoming messages under your profile.")
        
        st.subheader("Your Connected Accounts")
        st.write("- `user.primary@gmail.com`")
        st.write("- `user.work@company.com`")

        new_email = st.text_input("Add new email account address:")
        if st.button("Connect New Account"):
            if new_email.strip():
                st.success(f"Account link request initiated for {new_email}.")
            else:
                st.warning("Please enter a valid email address.")

    # --- TAB 3: Private Audit Logs ---
    with tab_logs:
        st.header("Your Private Audit Logs")
        st.caption(f"Showing scan history exclusively for username: **{username}**")

        user_logs = fetch_logs(username)
        display_logs = [
            {
                "Timestamp": log["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if hasattr(log["timestamp"], "strftime") else str(log["timestamp"]),
                "Type": log["check_type"],
                "Result": log["result"]
            }
            for log in user_logs
        ]
        
        if display_logs:
            st.table(display_logs)
        else:
            st.info("No audit logs found.")

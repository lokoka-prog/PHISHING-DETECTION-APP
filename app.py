import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from config import Config
from database import init_db, log_prediction, fetch_logs
from inference import PhishingPredictor
from url_checker import analyze_url
from email_fetcher import fetch_latest_emails
from plyer import notification
import sqlite3

# Set page title, favicon (page_icon), and layout
st.set_page_config(
    page_title="AI Phishing Detection Dashboard",
    page_icon="🛡️",  # You can replace this emoji with a file path like "assets/favicon.png"
    layout="wide"
)

init_db()
predictor = PhishingPredictor(Config.MODEL_PATH, Config.VECTORIZER_PATH)

st.title("🛡️ AI Email & URL Phishing Detector")

tab1, tab2, tab3, tab4 = st.tabs(["🔗 URL Checker", "📧 Real-time Email Monitor", "📊 Audit Logs", "📈 Performance History"])

with tab1:
    st.subheader("Analyze URL")
    url_input = st.text_input("Paste URL below:")
    if st.button("Check URL"):
        if url_input:
            pred, conf = analyze_url(url_input, predictor)
            log_prediction(url_input, "URL", f"{pred} ({conf:.2%})")
            if pred == "Phishing":
                st.error(f"⚠️ Warning: Phishing detected! (Confidence: {conf:.2%})")
                notification.notify(
                    title="Phishing Alert",
                    message=f"Phishing detected in URL! Confidence: {conf:.2%}",
                    app_name="AI Phishing Detector",
                )
            else:
                st.success(f"✅ Legitimate URL. (Confidence: {conf:.2%})")

with tab2:
    st.subheader("Email Credentials & Server Settings")
    email_user = st.text_input("IMAP Email", value=Config.EMAIL_USER)
    email_pass = st.text_input("App Password", value=Config.EMAIL_PASS, type="password")
    imap_server = st.text_input("IMAP Server", value=Config.IMAP_SERVER)

    if st.button("Fetch & Analyze Unread Emails"):
        with st.spinner("Fetching emails..."):
            emails, err = fetch_latest_emails(imap_server, Config.IMAP_PORT, email_user, email_pass)
            if err:
                st.error(f"Connection failed: {err}")
            elif not emails:
                st.info("No unread emails found.")
            else:
                for item in emails:
                    content = f"Subject: {item['subject']}\nBody: {item['body']}"
                    pred, conf = predictor.predict(content)
                    log_prediction(content, "Email", f"{pred} ({conf:.2%})")
                    if pred == "Phishing":
                        st.error(f"🚨 PHISHING ALERT | From: {item['sender']} | Subject: {item['subject']}")
                        notification.notify(
                            title="Phishing Email Detected",
                            message=f"From: {item['sender']} | Subject: {item['subject']}",
                            app_name="AI Phishing Detector",
                        )
                    else:
                        st.success(f"📩 Legitimate Email | From: {item['sender']} | Subject: {item['subject']}")

with tab3:
    st.subheader("Prediction Audit Logs")
    logs = fetch_logs()
    if logs:
        df = pd.DataFrame(logs, columns=["ID", "Content / Input", "Type", "Result", "Timestamp"])
        df = df[["Timestamp", "ID", "Type", "Result", "Content / Input"]]
        st.dataframe(df, use_container_width=True)
    else:
        st.write("No logs recorded yet.")

with tab4:
    st.subheader("Model Performance Trends")
    
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
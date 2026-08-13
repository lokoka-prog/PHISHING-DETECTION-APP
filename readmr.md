# AI-Powered Email & URL Phishing Detection System

An end-to-end Machine Learning solution designed to detect phishing attempts across URLs and email content in real time. Features an interactive Streamlit web application, background email processing, and automated logging.

---

## 📌 Features

* **URL Safety Analyzer**: Evaluates link structures, lexical features, and domain characteristics to detect malicious links.
* **Email Content Inspector**: Uses NLP models to analyze email body text and headers for phishing indicators.
* **Streamlit Dashboard**: User-friendly UI for manual text/URL input and visual risk scoring.
* **Database Logging**: Automatically records scan results and audit history in a local SQLite database.
* **Dockerized Deployment**: Fully containerized using `docker-compose` for consistent deployment across environments.

---

## 🛠️ Project Structure

```text
├── app.py                 # Main Streamlit web application
├── test_app.py            # Pytest test suite for model & pipeline validation
├── Makefile               # Task automation commands
├── Dockerfile             # Container configuration for application
├── docker-compose.yml     # Multi-container orchestrator
├── requirements.txt       # Python dependencies
└── README.md              # Project documentation
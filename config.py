import os
from dotenv import load_dotenv

# Load variables from the .env file into the environment
load_dotenv()

class Config:
    # Model Paths
    MODEL_PATH = "model.pkl"
    VECTORIZER_PATH = "vectorizer.pkl"
    
    # Fetch credentials securely from environment variables
    # The second argument acts as a fallback default if the .env variable is missing
    EMAIL_USER = os.getenv("EMAIL_USER", "default@example.com")
    EMAIL_PASS = os.getenv("EMAIL_PASS", "")
    IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
    IMAP_PORT = int(os.getenv("IMAP_PORT", 993))
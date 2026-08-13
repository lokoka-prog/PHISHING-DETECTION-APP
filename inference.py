import os
import joblib

class PhishingPredictor:
    def __init__(self, model_path="phishing_model.pkl", vectorizer_path="vectorizer.pkl"):
        self.model = None
        self.vectorizer = None
        if os.path.exists(model_path) and os.path.exists(vectorizer_path):
            self.model = joblib.load(model_path)
            self.vectorizer = joblib.load(vectorizer_path)

    def predict(self, text):
        if not self.model or not self.vectorizer:
            # Fallback heuristic rules for demonstration until model files are loaded
            suspicious = any(kw in text.lower() for kw in ["verify", "urgent", "login", "bank", "click here", "password", "update account"])
            return ("Phishing" if suspicious else "Legitimate"), 0.85
        
        vec = self.vectorizer.transform([text])
        pred = self.model.predict(vec)[0]
        prob = max(self.model.predict_proba(vec)[0])
        return ("Phishing" if pred == 1 else "Legitimate"), float(prob)
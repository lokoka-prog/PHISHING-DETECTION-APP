import re

def analyze_url(url, predictor):
    suspicious_patterns = [
        r"https?://[^\s/$.?#].[^\s]*@", 
        r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        r"-{2,}",
    ]
    has_pattern = any(re.search(p, url) for p in suspicious_patterns)
    prediction, confidence = predictor.predict(url)
    
    if has_pattern:
        prediction = "Phishing"
        confidence = max(confidence, 0.90)
        
    return prediction, confidence
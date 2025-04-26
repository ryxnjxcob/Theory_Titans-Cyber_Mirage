# model.py
import re

def analyze_url(url):
    """
    Basic heuristic-based phishing detection.
    """
    phishing_patterns = [
        r"free-", r"login-", r"secure-", r"verify-", r"update-", r"account-",
        r"paypal", r"banking", r"security", r"confirm", r"password", r"credential"
    ]
    
    for pattern in phishing_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return "unsafe"
    
    return "safe"

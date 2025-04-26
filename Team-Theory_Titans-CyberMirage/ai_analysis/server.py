import requests
import os

GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyCaOY-liN0yB68NbWvhndvPKicgNPBhmZs"

def check_google_safe_browsing(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {
            "clientId": "CyberMirage",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(api_url, json=payload)
    return response.json()

# Example usage
# print(check_google_safe_browsing("http://example.com"))

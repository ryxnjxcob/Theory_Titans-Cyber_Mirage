from flask import Flask, request, jsonify
from mcafee_scraper import check_website

app = Flask(__name__)

# Predefined phishing & malware test domains
PHISHING_DOMAINS = [
    "phishing.testing.google.test",
    "www.phishtank.com"
]

MALICIOUS_DOMAINS = [
    "malware.testing.google.test",
    "www.wicar.org"
]

@app.route("/analyze", methods=["GET"])
def analyze():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "URL parameter is missing"}), 400

    # Extract domain name from URL
    domain = url.split("//")[-1].split("/")[0]

    # Check if the domain is in known phishing/malware lists
    if domain in PHISHING_DOMAINS:
        return jsonify({"status": "⚠️ Phishing site detected!"})
    elif domain in MALICIOUS_DOMAINS:
        return jsonify({"status": "☠️ Malicious site detected!"})

    # Default: Check with McAfee WebAdvisor
    result = check_website(url)
    return jsonify({"status": result})

if __name__ == "__main__":
    app.run(port=5000, debug=True)

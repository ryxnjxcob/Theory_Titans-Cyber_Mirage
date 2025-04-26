// phishing_detector.js
console.log("Cyber Mirage Phishing Detector Loaded");

function analyzePage() {
    const suspiciousKeywords = ["login", "verify", "account", "password", "secure", "update", "confirm"];
    let foundSuspicious = false;
    
    suspiciousKeywords.forEach(keyword => {
        if (document.body.innerHTML.toLowerCase().includes(keyword)) {
            foundSuspicious = true;
        }
    });

    if (foundSuspicious) {
        chrome.runtime.sendMessage({ action: "flag_phishing", url: window.location.href }, (response) => {
            if (response.result === "unsafe") {
                alert("⚠️ Warning: This site may be a phishing attempt!");
            }
        });
    }
}

document.addEventListener("DOMContentLoaded", analyzePage);

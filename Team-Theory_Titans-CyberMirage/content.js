// Listen for messages from the popup or background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "fill_fake_data") {
        injectFakeData();
        sendResponse({ status: "Fake data filled" });
    } else if (message.action === "analyze_links") {
        analyzeAllLinks();
        sendResponse({ status: "Analyzing links" });
    }
});

// Function to inject fake data into form fields
function injectFakeData() {
    const fakeData = {
        name: "John Doe",
        email: "johndoe@example.com",
        phone: "+1234567890",
        address: "123 Fake Street, NY",
        password: "SecureP@ssw0rd"
    };

    document.querySelectorAll("input, textarea").forEach(input => {
        const inputName = input.name.toLowerCase();
        if (input.type === "text" && inputName.includes("name")) {
            input.value = fakeData.name;
        } else if (input.type === "email") {
            input.value = fakeData.email;
        } else if (input.type === "tel") {
            input.value = fakeData.phone;
        } else if (input.type === "password") {
            input.value = fakeData.password;
        } else if (input.type === "text" && inputName.includes("address")) {
            input.value = fakeData.address;
        }
    });
}

// Function to analyze all links on the page
function analyzeAllLinks() {
    document.querySelectorAll("a").forEach(link => {
        link.addEventListener("mouseenter", async (event) => {
            const url = event.target.href;
            if (!url) return;

            try {
                const expandedURL = await expandShortenedURL(url);
                const safetyStatus = await checkLinkSafety(expandedURL);
                showTooltip(event.target, safetyStatus);
            } catch (error) {
                console.error("Error analyzing link:", error);
                showTooltip(event.target, "⚠️ Error Checking Link");
            }
        });

        link.addEventListener("mouseleave", hideTooltip);
    });
}

// Function to check if a URL is malicious
async function checkLinkSafety(url) {
    return new Promise((resolve) => {
        if (!chrome.runtime?.sendMessage) {
            console.warn("Extension context invalidated.");
            return resolve("⚠️ Error: Extension Unavailable");
        }

        chrome.runtime.sendMessage({ action: "check_url", url: url }, (response) => {
            if (chrome.runtime.lastError || !response) {
                console.error("Chrome runtime error:", chrome.runtime.lastError);
                return resolve("⚠️ Error Checking Link");
            }

            if (response.result && response.result.includes("Malicious")) {
                resolve("❌ Malicious Link Detected!");
            } else {
                resolve("✅ Safe Link");
            }
        });
    });
}

// Function to request URL expansion from the background script
async function expandShortenedURL(shortenedURL) {
    return new Promise((resolve) => {
        if (!chrome.runtime?.sendMessage) {
            console.warn("Extension context invalidated.");
            return resolve(shortenedURL);
        }

        chrome.runtime.sendMessage({ action: "expand_url", url: shortenedURL }, (response) => {
            if (chrome.runtime.lastError || !response) {
                console.error("Chrome runtime error:", chrome.runtime.lastError);
                return resolve(shortenedURL);
            }

            resolve(response?.expandedURL || shortenedURL);
        });
    });
}

// Function to display a tooltip with the analysis result
function showTooltip(element, message) {
    // Remove any existing tooltip
    hideTooltip();

    let tooltip = document.createElement("div");
    tooltip.innerText = message;
    tooltip.style.position = "absolute";
    tooltip.style.background = message.includes("Malicious") ? "red" : "green";
    tooltip.style.color = "white";
    tooltip.style.padding = "6px 10px";
    tooltip.style.borderRadius = "5px";
    tooltip.style.fontSize = "14px";
    tooltip.style.zIndex = "10000";
    tooltip.style.pointerEvents = "none"; // Prevent interference with user interaction
    tooltip.id = "link-tooltip";
    document.body.appendChild(tooltip);

    // Function to update tooltip position dynamically
    function updateTooltipPosition(e) {
        tooltip.style.top = `${e.clientY + 15}px`;
        tooltip.style.left = `${e.clientX + 15}px`;
    }

    // Attach event listener to track mouse movement
    document.addEventListener("mousemove", updateTooltipPosition);

    // Remove tooltip when mouse leaves
    element.addEventListener("mouseleave", () => {
        hideTooltip();
        document.removeEventListener("mousemove", updateTooltipPosition);
    });
}

// Function to remove the tooltip when the user moves the mouse away
function hideTooltip() {
    let tooltip = document.getElementById("link-tooltip");
    if (tooltip) tooltip.remove();
}

// Initialize link analysis when the script loads
document.addEventListener("DOMContentLoaded", analyzeAllLinks);

function analyzeTextContent() {
    const suspiciousWords = [
        "verify", "login", "urgent", "update your info", "account suspended",
        "security alert", "click here", "act now", "limited time"
    ];
    const bodyText = document.body.innerText.toLowerCase();
    let score = 0;

    suspiciousWords.forEach(word => {
        if (bodyText.includes(word)) score++;
    });

    if (score >= 3) {
        console.warn("⚠️ Potential phishing keywords detected in page text");
        alert("⚠️ This website may be suspicious due to phishing-related keywords.");
    }
}

function generateDomFingerprint() {
    const tags = Array.from(document.querySelectorAll("*"))
        .map(el => el.tagName)
        .join(",");
    return tags;
}

function detectSpoofing() {
    const currentFingerprint = generateDomFingerprint();

    const gmailPattern = "HTML,HEAD,META,TITLE,LINK,BODY,DIV,DIV,INPUT,INPUT,BUTTON";
    const facebookPattern = "HTML,HEAD,META,TITLE,BODY,DIV,DIV,FORM,INPUT,INPUT,BUTTON";

    if (
        currentFingerprint.includes(gmailPattern) ||
        currentFingerprint.includes(facebookPattern)
    ) {
        alert("⚠️ This page may be mimicking Gmail or Facebook. Proceed with caution!");
    }
}
function detectSuspiciousBehavior() {
    const hiddenForms = [...document.querySelectorAll("form")].filter(f => {
        const style = getComputedStyle(f);
        return style.display === "none" || style.visibility === "hidden" || f.offsetHeight === 0;
    });

    const iframes = document.querySelectorAll("iframe");
    const forceDownloadLinks = [...document.querySelectorAll("a[download]")];

    if (hiddenForms.length > 0) {
        alert("⚠️ Hidden form fields detected — may be phishing.");
    }

    if (forceDownloadLinks.length > 0) {
        alert("⚠️ This site may trigger force downloads.");
    }

    if (iframes.length > 5) {
        alert("⚠️ Suspicious iframe usage detected.");
    }
}

document.addEventListener("DOMContentLoaded", () => {
    analyzeAllLinks();
    analyzeTextContent();
    detectSpoofing();
    detectSuspiciousBehavior();
});


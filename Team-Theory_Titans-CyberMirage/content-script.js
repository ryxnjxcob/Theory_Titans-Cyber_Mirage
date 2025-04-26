// Content script for link hover analysis
let currentHoverTimer = null
let currentTooltip = null
let isAnalyzing = false

// Create and inject CSS for the tooltips
const style = document.createElement("style")
style.textContent = `
  .security-tooltip {
    position: absolute;
    padding: 8px 12px;
    border-radius: 4px;
    font-size: 14px;
    z-index: 10000;
    max-width: 300px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    transition: opacity 0.3s;
    pointer-events: none;
  }
  .security-tooltip.loading {
    background-color: #f5f5f5;
    color: #333;
    border: 1px solid #ddd;
  }
  .security-tooltip.safe {
    background-color: #e8f5e9;
    color: #2e7d32;
    border: 1px solid #a5d6a7;
  }
  .security-tooltip.unsafe {
    background-color: #ffebee;
    color: #c62828;
    border: 1px solid #ef9a9a;
  }
  .security-tooltip.unknown {
    background-color: #fff8e1;
    color: #f57f17;
    border: 1px solid #ffe082;
  }
  .security-icon {
    margin-right: 8px;
    font-weight: bold;
  }
`
document.head.appendChild(style)

// Initialize the hover detection
function initLinkHoverAnalysis() {
  // Listen for mouseover events on all links
  document.addEventListener("mouseover", handleLinkHover)

  // Listen for mouseout events to remove tooltips
  document.addEventListener("mouseout", handleLinkMouseOut)

  console.log("Link hover analysis initialized")
}

// Handle link hover events
function handleLinkHover(event) {
  // Check if the hovered element is a link
  if (event.target.tagName === "A" && event.target.href) {
    const link = event.target
    const url = link.href

    // Skip javascript: links and empty links
    if (url.startsWith("javascript:") || url === "#") {
      return
    }

    // Clear any existing hover timer
    if (currentHoverTimer) {
      clearTimeout(currentHoverTimer)
    }

    // Set a small delay before analyzing to avoid unnecessary requests
    currentHoverTimer = setTimeout(() => {
      // Don't analyze if we're already analyzing this link
      if (isAnalyzing) return

      try {
        // Show loading tooltip
        showTooltip(link, "loading", "⏳ Analyzing link safety...")
        isAnalyzing = true

        console.log("Analyzing link:", url)

        // Check if extension context is still valid before sending message
        if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.id) {
          // Send message to background script to analyze the URL
          chrome.runtime.sendMessage({ action: "analyze_hover_link", url: url }, (response) => {
            isAnalyzing = false

            // Check for errors in the response
            if (chrome.runtime.lastError) {
              console.error("Runtime error:", chrome.runtime.lastError)
              showTooltip(link, "unknown", "❓ Error analyzing link")
              return
            }

            if (!response) {
              console.error("No response received from background script")
              showTooltip(link, "unknown", "❓ Could not analyze link")
              return
            }

            console.log("Received response:", response)

            // Determine tooltip type based on result
            if (response.isSafe) {
              showTooltip(link, "safe", "✅ Safe link")
            } else if (response.isMalicious) {
              showTooltip(link, "unsafe", "❌ Potentially unsafe link")
            } else {
              showTooltip(link, "unknown", "⚠️ Unknown safety status")
            }
          })
        } else {
          console.error("Extension context is no longer valid")
          isAnalyzing = false
          showTooltip(link, "unknown", "❓ Extension context invalid")
        }
      } catch (error) {
        console.error("Error in hover analysis:", error)
        isAnalyzing = false
        showTooltip(link, "unknown", "❓ Error analyzing link")
      }
    }, 500) // 500ms delay before analyzing
  }
}

// Handle mouse leaving a link
function handleLinkMouseOut(event) {
  if (event.target.tagName === "A") {
    // Clear hover timer if it exists
    if (currentHoverTimer) {
      clearTimeout(currentHoverTimer)
      currentHoverTimer = null
    }

    // Remove tooltip if it exists
    removeTooltip()
  }
}

// Show tooltip near the link
function showTooltip(element, type, message) {
  try {
    // Remove existing tooltip if there is one
    removeTooltip()

    // Create new tooltip
    const tooltip = document.createElement("div")
    tooltip.className = `security-tooltip ${type}`
    tooltip.innerHTML = `<span class="security-icon">${getIconForType(type)}</span>${message}`

    // Position the tooltip near the link
    const rect = element.getBoundingClientRect()
    tooltip.style.left = `${rect.left + window.scrollX}px`
    tooltip.style.top = `${rect.bottom + window.scrollY + 5}px` // 5px below the link

    // Add to document
    document.body.appendChild(tooltip)
    currentTooltip = tooltip
  } catch (error) {
    console.error("Error showing tooltip:", error)
  }
}

// Get appropriate icon for tooltip type
function getIconForType(type) {
  switch (type) {
    case "safe":
      return "✅"
    case "unsafe":
      return "❌"
    case "unknown":
      return "⚠️"
    case "loading":
      return "⏳"
    default:
      return "❓"
  }
}

// Remove tooltip
function removeTooltip() {
  if (currentTooltip) {
    try {
      currentTooltip.remove()
    } catch (error) {
      console.error("Error removing tooltip:", error)
    }
    currentTooltip = null
  }
}

// Function to get external resources on the page
function getExternalResources() {
  const resources = []

  // Get all script srcs
  document.querySelectorAll("script[src]").forEach((script) => {
    resources.push(script.src)
  })

  // Get all iframes
  document.querySelectorAll("iframe[src]").forEach((iframe) => {
    resources.push(iframe.src)
  })

  // Get all anchor links
  document.querySelectorAll("a[href]").forEach((link) => {
    const href = link.href
    if (href.startsWith("http")) resources.push(href)
  })

  return [...new Set(resources)] // Remove duplicates
}

// Function to run a full scan of the page
function runFullScanAndReport() {
  const suspiciousWords = [
    "verify",
    "login",
    "urgent",
    "update your info",
    "account suspended",
    "security alert",
    "click here",
    "act now",
    "limited time",
  ]
  const bodyText = document.body.innerText.toLowerCase()

  let keywordScore = 0
  suspiciousWords.forEach((word) => {
    if (bodyText.includes(word)) keywordScore++
  })

  const hiddenForms = [...document.querySelectorAll("form")].filter((f) => {
    const style = getComputedStyle(f)
    return style.display === "none" || style.visibility === "hidden" || f.offsetHeight === 0
  })

  const downloadLinks = [...document.querySelectorAll("a[download]")]
  const popupScore = detectPopupBehavior()

  // Send the result back to popup
  chrome.runtime.sendMessage({
    type: "SCAN_RESULT",
    data: {
      keywordScore: keywordScore,
      hiddenFormsCount: hiddenForms.length,
      downloadLinksCount: downloadLinks.length,
      popupScore: popupScore,
    },
  })
}

// Simple popup detection
function detectPopupBehavior() {
  let score = 0
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      if (
        mutation.addedNodes &&
        [...mutation.addedNodes].some(
          (node) => node.nodeType === 1 && node.tagName === "DIV" && node.innerText.length > 50,
        )
      ) {
        score++
      }
    })
  })

  observer.observe(document.body, { childList: true, subtree: true })
  return score
}

// Add a reconnection mechanism
function checkExtensionConnection() {
  try {
    if (!chrome.runtime || !chrome.runtime.id) {
      console.log("Extension context invalid, content script will stop working")
      // Clean up event listeners
      document.removeEventListener("mouseover", handleLinkHover)
      document.removeEventListener("mouseout", handleLinkMouseOut)
      return false
    }
    return true
  } catch (e) {
    console.log("Extension disconnected:", e)
    // Clean up event listeners
    document.removeEventListener("mouseover", handleLinkHover)
    document.removeEventListener("mouseout", handleLinkMouseOut)
    return false
  }
}

// Declare chrome variable if it's not already defined
if (typeof chrome === "undefined") {
  chrome = {}
}

// Listen for messages from the popup or background script
try {
  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.id) {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      console.log("Content script received message:", message)

      if (message.action === "toggle_hover_analysis") {
        // Toggle the hover analysis feature
        if (message.enabled) {
          console.log("Enabling hover analysis")
          initLinkHoverAnalysis()
        } else {
          console.log("Disabling hover analysis")
          document.removeEventListener("mouseover", handleLinkHover)
          document.removeEventListener("mouseout", handleLinkMouseOut)
        }
        sendResponse({ success: true })
      } else if (message.action === "deep_scan_resources") {
        const links = getExternalResources()
        sendResponse({ resources: links })
      } else if (message.action === "run_full_scan") {
        runFullScanAndReport()
        sendResponse({ status: "Scanning..." })
      }
      return true
    })
  }
} catch (error) {
  console.error("Error setting up message listener:", error)
}

// Initialize when the page is fully loaded
if (document.readyState === "complete") {
  initLinkHoverAnalysis()
} else {
  window.addEventListener("load", initLinkHoverAnalysis)
}

// Check connection periodically
setInterval(checkExtensionConnection, 5000)

// Log that the content script has loaded
console.log("Security content script loaded")
// This is a simplified content script to fix the hover analysis display issue

// Listen for messages from the background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "show_hover_result") {
    const linkElement = document.querySelector(`[data-link-id="${message.linkId}"]`)
    if (linkElement) {
      // Determine the correct status to display
      let displayStatus = "unknown"

      if (message.result.isSafe) {
        displayStatus = "safe"
      } else if (message.result.isMalicious) {
        displayStatus = "malicious"
      } else if (message.result.error) {
        displayStatus = "error"
      }

      // Show the indicator with the correct status
      showAnalysisIndicator(linkElement, displayStatus)
    }
  }
})

// Visual indicator for link analysis
function showAnalysisIndicator(linkElement, status) {
  // Remove any existing indicators
  const existingIndicator = document.querySelector(".link-analysis-indicator")
  if (existingIndicator) {
    existingIndicator.remove()
  }

  // Create new indicator
  const indicator = document.createElement("div")
  indicator.className = "link-analysis-indicator"

  // Position near the link
  const rect = linkElement.getBoundingClientRect()
  indicator.style.position = "fixed"
  indicator.style.left = `${rect.right + 5}px`
  indicator.style.top = `${rect.top}px`
  indicator.style.zIndex = "9999"
  indicator.style.padding = "3px 8px"
  indicator.style.borderRadius = "4px"
  indicator.style.fontSize = "12px"
  indicator.style.fontWeight = "bold"

  // Set content based on status
  switch (status) {
    case "loading":
      indicator.textContent = "⏳ Analyzing..."
      indicator.style.backgroundColor = "#f0f0f0"
      indicator.style.color = "#666"
      break
    case "safe":
      indicator.textContent = "✅ Safe"
      indicator.style.backgroundColor = "#e6f7e6"
      indicator.style.color = "#2e7d32"
      break
    case "malicious":
      indicator.textContent = "⚠️ Dangerous"
      indicator.style.backgroundColor = "#ffebee"
      indicator.style.color = "#c62828"
      break
    case "unknown":
      indicator.textContent = "❓ Unknown"
      indicator.style.backgroundColor = "#fff8e1"
      indicator.style.color = "#f57c00"
      break
    case "error":
      indicator.textContent = "❌ Error"
      indicator.style.backgroundColor = "#f5f5f5"
      indicator.style.color = "#757575"
      break
  }

  // Add to page
  document.body.appendChild(indicator)

  // Remove after 3 seconds if not 'loading'
  if (status !== "loading") {
    setTimeout(() => {
      indicator.remove()
    }, 3000)
  }
}

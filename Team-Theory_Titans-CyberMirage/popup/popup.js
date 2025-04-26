/**
 * Security Extension Popup Script - Comprehensive Fix
 * Handles UI interactions and communicates with background script
 */

// Initialize popup when DOM is loaded
document.addEventListener("DOMContentLoaded", initializePopup)

// Global variables for debugging
let DEBUG_MODE = true
let lastScanResults = null

// Main initialization function
function initializePopup() {
  debugLog("Initializing popup...")

  // Get UI elements
  const elements = {
    scanButton: document.getElementById("scanButton"),
    scanAndSecureButton: document.getElementById("scanAndSecureButton"),
    deepScanButton: document.getElementById("deepScanButton"),
    fakeFillButton: document.getElementById("fakeFillButton"),
    resetStatsButton: document.getElementById("resetStats"),
    scanLinksBtn: document.getElementById("scanLinksBtn"),
    reportBtn: document.getElementById("reportBtn"),
    saveSettingsBtn: document.getElementById("saveSettings"),
    apiKeyInput: document.getElementById("apiKey"),
    enableHoverCheckbox: document.getElementById("enableHoverCheck"),
    debugModeCheckbox: document.getElementById("debugMode"),
    generateReportBtn: document.getElementById("generateReportBtn"),
  }

  // Load saved settings and statistics
  loadSavedSettings()
  loadStatistics()

  // Set up event listeners
  setupEventListeners(elements)

  // Show report count if available
  if (elements.reportBtn) {
    showReportCountForCurrentPage()
  }

  // Listen for scan results from content script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "SCAN_RESULT") {
      updatePopupUI(message.data)
    } else if (message.type === "DEBUG_LOG" && DEBUG_MODE) {
      console.log("[Content Script]", message.data)
    }
    return true
  })

  // Check if we're in a valid tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs.length || !tabs[0].url || tabs[0].url.startsWith("chrome://")) {
      disableScanButtons(elements)
      showError("Cannot scan this page. Please navigate to a website.")
    }
  })

  // Add this to your popup.js file, inside the initializePopup function
  // after the other event listeners

  // Listen for stats updates from background script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "STATS_UPDATED") {
      console.log("Received stats update:", message.data)
      updateStatisticsUI(message.data)
      return true
    }
    return true
  })
}

// Disable scan buttons for invalid pages
function disableScanButtons(elements) {
  const buttons = [elements.scanButton, elements.scanAndSecureButton, elements.deepScanButton, elements.scanLinksBtn]

  buttons.forEach((button) => {
    if (button) {
      button.disabled = true
      button.classList.add("disabled")
    }
  })
}

// Debug logging function
function debugLog(message, data) {
  if (DEBUG_MODE) {
    if (data) {
      console.log(`[Security Extension] ${message}`, data)
    } else {
      console.log(`[Security Extension] ${message}`)
    }
  }
}

// Load saved API key and settings
function loadSavedSettings() {
  chrome.storage.local.get(["apiKey", "enableHoverCheck", "debugMode"], (result) => {
    const apiKeyInput = document.getElementById("apiKey")
    const enableHoverCheckbox = document.getElementById("enableHoverCheck")
    const debugModeCheckbox = document.getElementById("debugMode")

    if (apiKeyInput && result.apiKey) {
      apiKeyInput.value = result.apiKey
    }

    if (enableHoverCheckbox) {
      const enableHoverCheck = result.enableHoverCheck !== undefined ? result.enableHoverCheck : true
      enableHoverCheckbox.checked = enableHoverCheck
    }

    if (debugModeCheckbox) {
      DEBUG_MODE = result.debugMode !== undefined ? result.debugMode : false
      debugModeCheckbox.checked = DEBUG_MODE
    }
  })
}

// Set up all event listeners
function setupEventListeners(elements) {
  // Main action buttons
  if (elements.scanButton) {
    elements.scanButton.addEventListener("click", analyzeSite)
  }

  if (elements.scanAndSecureButton) {
    elements.scanAndSecureButton.addEventListener("click", scanAndSecureSite)
  }

  if (elements.deepScanButton) {
    elements.deepScanButton.addEventListener("click", performDeepScan)
  }

  if (elements.fakeFillButton) {
    elements.fakeFillButton.addEventListener("click", injectFakeData)
  }

  if (elements.resetStatsButton) {
    elements.resetStatsButton.addEventListener("click", resetStatistics)
  }

  // Deep scan links button
  if (elements.scanLinksBtn) {
    elements.scanLinksBtn.addEventListener("click", () => {
      showLoading("Scanning links...")
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs.length) {
          hideLoading()
          showError("No active tab found.")
          return
        }

        chrome.tabs.sendMessage(tabs[0].id, { action: "deep_scan_resources" }, async (response) => {
          hideLoading()
          if (chrome.runtime.lastError) {
            showError(`Error: ${chrome.runtime.lastError.message}`)
            return
          }

          if (response && response.resources) {
            const results = await scanLinksWithVirusTotal(response.resources)
            displayScanResults(results)
          } else {
            showError("Could not retrieve resources from page")
          }
        })
      })
    })
  }

  // Report button
  if (elements.reportBtn) {
    elements.reportBtn.addEventListener("click", () => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs.length) {
          showError("No active tab found.")
          return
        }

        const url = tabs[0].url
        reportSuspiciousPage(url)
      })
    })
  }

  // Save settings button
  if (elements.saveSettingsBtn) {
    elements.saveSettingsBtn.addEventListener("click", saveSettings)
  }

  // Debug mode checkbox
  if (elements.debugModeCheckbox) {
    elements.debugModeCheckbox.addEventListener("change", (e) => {
      DEBUG_MODE = e.target.checked
      chrome.storage.local.set({ debugMode: DEBUG_MODE })
      debugLog(`Debug mode ${DEBUG_MODE ? "enabled" : "disabled"}`)
    })
  }

  // Add this inside the setupEventListeners function after the other button event listeners
  if (elements.generateReportBtn) {
    elements.generateReportBtn.addEventListener("click", generateWebsiteReport)
  }
}

// Save user settings
function saveSettings() {
  const apiKey = document.getElementById("apiKey").value.trim()
  const enableHoverCheck = document.getElementById("enableHoverCheck").checked
  const debugMode = document.getElementById("debugMode")?.checked || false

  // Save to Chrome storage
  chrome.storage.local.set(
    {
      apiKey: apiKey,
      enableHoverCheck: enableHoverCheck,
      debugMode: debugMode,
    },
    () => {
      if (chrome.runtime.lastError) {
        showError(`Error saving settings: ${chrome.runtime.lastError.message}`)
        return
      }

      // Show saved confirmation
      const saveButton = document.getElementById("saveSettings")
      const originalText = saveButton.textContent
      saveButton.textContent = "Saved!"
      saveButton.style.backgroundColor = "#2196F3"

      // Revert button text after 2 seconds
      setTimeout(() => {
        saveButton.textContent = originalText
        saveButton.style.backgroundColor = ""
      }, 2000)

      // Update global debug mode
      DEBUG_MODE = debugMode
    },
  )

  // Update hover check status in all tabs
  updateHoverCheckInAllTabs(enableHoverCheck)
}

// Update hover check setting in all open tabs
function updateHoverCheckInAllTabs(enableHoverCheck) {
  chrome.tabs.query({}, (tabs) => {
    tabs.forEach((tab) => {
      try {
        // Skip chrome:// URLs
        if (tab.url.startsWith("chrome://")) return

        chrome.tabs.sendMessage(
          tab.id,
          {
            action: "toggle_hover_analysis",
            enabled: enableHoverCheck,
          },
          (response) => {
            if (chrome.runtime.lastError) {
              debugLog(`Could not send message to tab: ${tab.id}`, chrome.runtime.lastError)
            }
          },
        )
      } catch (err) {
        debugLog(`Error sending message to tab: ${tab.id}`, err)
      }
    })
  })
}

// Function to analyze site safety
function analyzeSite() {
  showLoading("Analyzing site...")

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs.length) {
      hideLoading()
      showError("No active tab found.")
      return
    }

    chrome.runtime.sendMessage({ action: "analyze_site", url: tabs[0].url }, (response) => {
      hideLoading()

      if (chrome.runtime.lastError) {
        debugLog("Analysis Error:", chrome.runtime.lastError)
        showError(`Error analyzing site: ${chrome.runtime.lastError.message}`)
        return
      }

      if (!response || !response.result) {
        showError("Error analyzing site. Please try again.")
        return
      }

      updateScanResult(response.result)
      updateStoredStatistics(response.result)
    })
  })
}

// Function to analyze and secure the site
function scanAndSecureSite() {
  showLoading("Scanning and securing site...")

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs.length) {
      hideLoading()
      showError("No active tab found.")
      return
    }

    const tabUrl = tabs[0].url
    analyzeAndSecureSite(tabUrl)
  })
}

// Analyze site and apply security measures
function analyzeAndSecureSite(url) {
  chrome.runtime.sendMessage({ action: "analyze_site", url: url }, (response) => {
    hideLoading()

    if (chrome.runtime.lastError) {
      debugLog("Analysis Error:", chrome.runtime.lastError)
      showError(`Error analyzing site: ${chrome.runtime.lastError.message}`)
      return
    }

    if (!response || !response.result) {
      showError("Error analyzing site. Please try again.")
      return
    }

    const scanResult = response.result
    updateScanResult(scanResult) // Display the result
    updateStoredStatistics(scanResult)

    // Apply additional security features
    enforceHttps(url)
    blockMaliciousScripts(url)

    showSuccess("Security measures applied!")
  })
}

// Function to perform a deep scan of the website
function performDeepScan() {
  const scanResultsContainer = document.getElementById("deepScanResults")
  if (scanResultsContainer) {
    scanResultsContainer.innerHTML = '<div class="loading">Scanning website for vulnerabilities...</div>'
  }

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs.length) {
      showError("No active tab found.")
      return
    }

    // Execute script to get all website code
    chrome.scripting
      .executeScript({
        target: { tabId: tabs[0].id },
        function: getWebsiteCode,
      })
      .then((results) => {
        if (!results || !results[0] || !results[0].result) {
          showError("Could not retrieve website code.")
          return
        }

        const websiteCode = results[0].result
        debugLog("Retrieved website code:", websiteCode)

        // Perform deep vulnerability scan
        const vulnerabilities = improvedDeepVulnerabilityScan(websiteCode)
        lastScanResults = vulnerabilities

        debugLog("Vulnerabilities found:", vulnerabilities)

        // Generate patches for found vulnerabilities
        const patchedCode = suggestPatch(websiteCode, vulnerabilities)

        // Display results
        displayDeepScanResults(vulnerabilities, patchedCode)

        // Update statistics
        chrome.storage.local.get(["deepScanCount"], (data) => {
          const newCount = (data.deepScanCount || 0) + 1
          chrome.storage.local.set({ deepScanCount: newCount })
        })
      })
      .catch((error) => {
        console.error("Deep Scan Error:", error)
        showError(`Error performing deep scan: ${error.message}`)
      })
  })
}

// IMPROVED: Function to get all website code
function getWebsiteCode() {
  try {
    // Get HTML
    const htmlContent = document.documentElement.outerHTML

    // Get all script content
    const scripts = []

    // Get inline scripts
    document.querySelectorAll("script:not([src])").forEach((script) => {
      if (script.textContent) {
        scripts.push({
          type: "inline",
          content: script.textContent,
          location: getElementPath(script),
        })
      }
    })

    // Get external scripts
    const externalScripts = []
    document.querySelectorAll("script[src]").forEach((script) => {
      externalScripts.push({
        type: "external",
        src: script.src,
        location: getElementPath(script),
      })
    })

    // Get event handlers
    const eventHandlers = []
    const allElements = document.querySelectorAll("*")
    const eventAttributes = [
      "onclick",
      "onmouseover",
      "onmouseout",
      "onkeydown",
      "onkeyup",
      "onsubmit",
      "onload",
      "onerror",
    ]

    allElements.forEach((el) => {
      eventAttributes.forEach((attr) => {
        if (el.hasAttribute(attr)) {
          eventHandlers.push({
            type: "event",
            element: getElementPath(el),
            attribute: attr,
            content: el.getAttribute(attr),
          })
        }
      })
    })

    // Get forms
    const forms = []
    document.querySelectorAll("form").forEach((form) => {
      const formData = {
        action: form.action,
        method: form.method,
        hasCSRF: false,
        inputs: [],
      }

      // Check for CSRF tokens
      form.querySelectorAll("input").forEach((input) => {
        const name = input.name ? input.name.toLowerCase() : ""
        if (name.includes("csrf") || name.includes("token") || name === "_token") {
          formData.hasCSRF = true
        }

        formData.inputs.push({
          type: input.type,
          name: input.name,
          id: input.id,
        })
      })

      forms.push(formData)
    })

    // Get iframes
    const iframes = []
    document.querySelectorAll("iframe").forEach((iframe) => {
      iframes.push({
        src: iframe.src,
        sandbox: iframe.sandbox ? iframe.sandbox.value : null,
        location: getElementPath(iframe),
      })
    })

    // Helper function to get element path
    function getElementPath(el) {
      if (!el) return ""

      let path = ""
      while (el && el.nodeType === Node.ELEMENT_NODE) {
        let selector = el.nodeName.toLowerCase()
        if (el.id) {
          selector += "#" + el.id
          path = selector + (path ? " > " + path : "")
          break
        } else {
          let sibling = el
          let nth = 1
          while ((sibling = sibling.previousElementSibling)) {
            if (sibling.nodeName.toLowerCase() === selector) nth++
          }
          if (nth !== 1) selector += ":nth-of-type(" + nth + ")"
        }
        path = selector + (path ? " > " + path : "")
        el = el.parentNode
      }
      return path
    }

    return {
      html: htmlContent,
      scripts: scripts,
      externalScripts: externalScripts,
      eventHandlers: eventHandlers,
      forms: forms,
      iframes: iframes,
    }
  } catch (error) {
    console.error("Error in getWebsiteCode:", error)
    return { error: error.message }
  }
}

// IMPROVED: Function to perform deep vulnerability scan
function improvedDeepVulnerabilityScan(websiteCode) {
  try {
    const vulnerabilities = []

    // Check HTML for vulnerabilities
    const htmlVulnerabilities = improvedScanHtmlForVulnerabilities(websiteCode.html)
    vulnerabilities.push(...htmlVulnerabilities)

    // Check scripts for vulnerabilities
    if (websiteCode.scripts && Array.isArray(websiteCode.scripts)) {
      websiteCode.scripts.forEach((script) => {
        if (script && script.type === "inline" && script.content) {
          const scriptVulnerabilities = improvedScanScriptForVulnerabilities(script.content)

          // Add location information to each vulnerability
          scriptVulnerabilities.forEach((vuln) => {
            vuln.location = script.location || "Unknown script location"
          })

          vulnerabilities.push(...scriptVulnerabilities)
        }
      })
    }

    // Check event handlers
    if (websiteCode.eventHandlers && Array.isArray(websiteCode.eventHandlers)) {
      websiteCode.eventHandlers.forEach((handler) => {
        if (handler && handler.content) {
          // Check for potentially dangerous event handlers
          if (
            handler.content.includes("eval(") ||
            handler.content.includes("document.write") ||
            handler.content.includes("innerHTML")
          ) {
            vulnerabilities.push({
              type: "event-handler",
              severity: "high",
              description: "Potentially unsafe code in event handler",
              code: `<element ${handler.attribute}="${handler.content}">`,
              location: handler.element,
              fix: "Move code to a separate JavaScript file and use addEventListener",
            })
          }
        }
      })
    }

    // Check forms for CSRF protection
    if (websiteCode.forms && Array.isArray(websiteCode.forms)) {
      websiteCode.forms.forEach((form) => {
        if (form.method.toLowerCase() === "post" && !form.hasCSRF) {
          vulnerabilities.push({
            type: "CSRF",
            severity: "medium",
            description: "Form without CSRF protection",
            code: `<form action="${form.action}" method="post">...</form>`,
            fix: 'Add CSRF token to the form: <input type="hidden" name="_token" value="...">',
          })
        }
      })
    }

    // Check iframes for sandbox attribute
    if (websiteCode.iframes && Array.isArray(websiteCode.iframes)) {
      websiteCode.iframes.forEach((iframe) => {
        if (!iframe.sandbox) {
          vulnerabilities.push({
            type: "iframe",
            severity: "medium",
            description: "iframe without sandbox attribute",
            code: `<iframe src="${iframe.src}"></iframe>`,
            location: iframe.location,
            fix: `<iframe src="${iframe.src}" sandbox="allow-scripts allow-same-origin"></iframe>`,
          })
        }
      })
    }

    return vulnerabilities
  } catch (error) {
    console.error("Error in improvedDeepVulnerabilityScan:", error)
    return [
      {
        type: "error",
        severity: "high",
        description: `Error scanning for vulnerabilities: ${error.message}`,
        code: "N/A",
        fix: "Please try again or contact support",
      },
    ]
  }
}

// IMPROVED: Function to scan HTML for vulnerabilities
function improvedScanHtmlForVulnerabilities(html) {
  const vulnerabilities = []

  try {
    // Check for inline event handlers (potential XSS)
    const inlineEventHandlerRegex = /\son\w+\s*=\s*["'](?!javascript:void$$0$$)([^"']*?)["']/gi
    let match
    while ((match = inlineEventHandlerRegex.exec(html)) !== null) {
      const eventHandler = match[0]
      const handlerCode = match[1]

      // Only flag if the handler contains potentially dangerous code
      if (
        handlerCode.includes("eval") ||
        handlerCode.includes("document.write") ||
        handlerCode.includes("innerHTML") ||
        handlerCode.includes("location.href=") ||
        handlerCode.includes("window.open")
      ) {
        vulnerabilities.push({
          type: "XSS",
          severity: "high",
          description: "Potentially dangerous inline JavaScript event handler",
          code: eventHandler,
          fix: "Use addEventListener in separate JavaScript files",
        })
      }
    }

    // Check for forms without CSRF protection
    if (
      html.match(/<form[^>]*method\s*=\s*["']post["'][^>]*>/gi) &&
      !html.match(/<input[^>]*name\s*=\s*["'](csrf|token|_token|authenticity_token)["'][^>]*>/gi)
    ) {
      vulnerabilities.push({
        type: "CSRF",
        severity: "medium",
        description: "Form without CSRF protection",
        code: '<form method="post">...</form>',
        fix: 'Add CSRF token to all forms: <input type="hidden" name="_token" value="...">',
      })
    }

    // Check for iframes without sandbox
    if (html.match(/<iframe[^>]*>/gi) && !html.match(/<iframe[^>]*sandbox\s*=\s*["'][^"']*["'][^>]*>/gi)) {
      vulnerabilities.push({
        type: "iframe",
        severity: "medium",
        description: "iframes without sandbox attribute",
        code: '<iframe src="..."></iframe>',
        fix: '<iframe src="..." sandbox="allow-scripts allow-same-origin"></iframe>',
      })
    }

    // Check for meta tags with unsafe CSP
    if (!html.match(/<meta[^>]*http-equiv\s*=\s*["']Content-Security-Policy["'][^>]*>/gi)) {
      vulnerabilities.push({
        type: "CSP",
        severity: "medium",
        description: "No Content Security Policy (CSP) meta tag",
        code: "<head>...</head>",
        fix: '<head>\n  <meta http-equiv="Content-Security-Policy" content="default-src \'self\'">\n  ...\n</head>',
      })
    }

    // Check for external scripts without integrity attribute
    const externalScriptRegex = /<script[^>]*src\s*=\s*["']([^"']+)["'][^>]*>/gi
    while ((match = externalScriptRegex.exec(html)) !== null) {
      const scriptTag = match[0]
      const scriptSrc = match[1]

      // Only check for scripts from CDNs
      if (scriptSrc.includes("cdn.") || scriptSrc.includes("jsdelivr") || scriptSrc.includes("unpkg")) {
        if (!scriptTag.includes("integrity=")) {
          vulnerabilities.push({
            type: "SRI",
            severity: "medium",
            description: "External script without Subresource Integrity (SRI) hash",
            code: scriptTag,
            fix: `<script src="${scriptSrc}" integrity="sha384-..." crossorigin="anonymous"></script>`,
          })
        }
      }
    }
  } catch (error) {
    console.error("Error in improvedScanHtmlForVulnerabilities:", error)
    vulnerabilities.push({
      type: "error",
      severity: "high",
      description: `Error scanning HTML: ${error.message}`,
      code: "N/A",
      fix: "Please try again or contact support",
    })
  }

  return vulnerabilities
}

// IMPROVED: Function to scan JavaScript for vulnerabilities
function improvedScanScriptForVulnerabilities(script) {
  const vulnerabilities = []

  try {
    // Check for eval usage
    const evalRegex = /\beval\s*\(/g
    if (evalRegex.test(script)) {
      vulnerabilities.push({
        type: "eval",
        severity: "high",
        description: "Use of eval() can lead to code injection",
        code: "eval(userInput)",
        fix: "Replace with safer alternatives like JSON.parse() for JSON data",
      })
    }

    // Check for Function constructor (similar to eval)
    const functionConstructorRegex = /new\s+Function\s*\(/g
    if (functionConstructorRegex.test(script)) {
      vulnerabilities.push({
        type: "Function",
        severity: "high",
        description: "Use of Function constructor can lead to code injection",
        code: "new Function(userInput)",
        fix: "Avoid dynamically creating functions from strings",
      })
    }

    // Check for document.write
    const documentWriteRegex = /document\.write\s*\(/g
    if (documentWriteRegex.test(script)) {
      vulnerabilities.push({
        type: "document.write",
        severity: "medium",
        description: "document.write() can be exploited in XSS attacks",
        code: "document.write(userInput)",
        fix: "Use safer DOM manipulation methods like element.textContent or element.appendChild()",
      })
    }

    // Check for innerHTML
    const innerHTMLRegex = /\.innerHTML\s*=/g
    if (innerHTMLRegex.test(script)) {
      vulnerabilities.push({
        type: "innerHTML",
        severity: "medium",
        description: "Direct use of innerHTML may cause XSS vulnerabilities",
        code: "element.innerHTML = userInput",
        fix: "Use element.textContent for text or DOMPurify.sanitize() for HTML",
      })
    }

    // Check for outerHTML
    const outerHTMLRegex = /\.outerHTML\s*=/g
    if (outerHTMLRegex.test(script)) {
      vulnerabilities.push({
        type: "outerHTML",
        severity: "medium",
        description: "Direct use of outerHTML may cause XSS vulnerabilities",
        code: "element.outerHTML = userInput",
        fix: "Use safer DOM manipulation methods",
      })
    }

    // Check for insertAdjacentHTML
    const insertAdjacentHTMLRegex = /\.insertAdjacentHTML\s*\(/g
    if (insertAdjacentHTMLRegex.test(script)) {
      vulnerabilities.push({
        type: "insertAdjacentHTML",
        severity: "medium",
        description: "insertAdjacentHTML can be vulnerable to XSS",
        code: 'element.insertAdjacentHTML("beforeend", userInput)',
        fix: "Use element.insertAdjacentText or DOMPurify.sanitize()",
      })
    }

    // Check for SQL injection patterns
    const sqlInjectionRegex = /SELECT\s+.+\s+FROM\s+.+\s+WHERE\s+.+\s*=\s*['"].*['"]\s*\+/gi
    if (sqlInjectionRegex.test(script)) {
      // Declare userName here
      let userName
      vulnerabilities.push({
        type: "SQL",
        severity: "high",
        description: "Possible SQL injection pattern detected",
        code: 'SELECT * FROM users WHERE name = "' + userName + '"',
        fix: "Use parameterized queries or prepared statements",
      })
    }

    // Check for path traversal
    const pathTraversalRegex = /\b(?:require|fs\.read|fs\.open|path\.join)\s*$$\s*['"]*.*['"]*\s*\+\s*.*$$/g
    if (pathTraversalRegex.test(script)) {
      vulnerabilities.push({
        type: "path",
        severity: "high",
        description: "Possible path traversal vulnerability",
        code: 'require("../../../" + userInput)',
        fix: "Validate and sanitize file paths, use path.normalize()",
      })
    }

    // Check for DOM-based XSS sinks
    const domXssSinkRegex =
      /\b(?:location|location\.href|location\.hash|location\.search|document\.URL|document\.documentURI|document\.referrer)\b/g
    if (domXssSinkRegex.test(script)) {
      vulnerabilities.push({
        type: "DOM-XSS",
        severity: "high",
        description: "Potential DOM-based XSS sink detected",
        code: "document.write(location.hash.substring(1))",
        fix: "Sanitize user-controlled data before inserting into the DOM",
      })
    }

    // Check for insecure random number generation
    const insecureRandomRegex = /Math\.random\s*$$\s*$$/g
    if (
      insecureRandomRegex.test(script) &&
      (script.includes("token") || script.includes("key") || script.includes("password") || script.includes("auth"))
    ) {
      vulnerabilities.push({
        type: "random",
        severity: "medium",
        description: "Insecure random number generation for security-sensitive operations",
        code: "const token = Math.random().toString(36)",
        fix: "Use crypto.getRandomValues() for cryptographically secure random values",
      })
    }

    // Check for setTimeout/setInterval with string arguments (similar to eval)
    const setTimeoutRegex = /\b(?:setTimeout|setInterval)\s*\(\s*['"`]/g
    if (setTimeoutRegex.test(script)) {
      vulnerabilities.push({
        type: "setTimeout",
        severity: "medium",
        description: "setTimeout/setInterval with string argument acts like eval",
        code: 'setTimeout("alert(userInput)", 100)',
        fix: "Use function references: setTimeout(() => alert(userInput), 100)",
      })
    }

    // Check for postMessage without origin check
    if (script.includes("postMessage(") && !script.includes("event.origin")) {
      vulnerabilities.push({
        type: "postMessage",
        severity: "medium",
        description: "postMessage without origin verification",
        code: 'window.addEventListener("message", (event) => { processMessage(event.data); })',
        fix: 'Always verify origin: window.addEventListener("message", (event) => { if (event.origin === "https://trusted-site.com") { processMessage(event.data); } })',
      })
    }

    // Check for insecure cookie settings
    if (script.includes("document.cookie") && !script.includes("Secure") && !script.includes("HttpOnly")) {
      vulnerabilities.push({
        type: "cookie",
        severity: "medium",
        description: "Insecure cookie settings detected",
        code: 'document.cookie = "sessionId=123"',
        fix: 'Set secure flags: document.cookie = "sessionId=123; Secure; HttpOnly; SameSite=Strict"',
      })
    }
  } catch (error) {
    console.error("Error in improvedScanScriptForVulnerabilities:", error)
    vulnerabilities.push({
      type: "error",
      severity: "high",
      description: `Error scanning JavaScript: ${error.message}`,
      code: "N/A",
      fix: "Please try again or contact support",
    })
  }

  return vulnerabilities
}

// Function to suggest patches for vulnerabilities
function suggestPatch(websiteCode, vulnerabilities) {
  let patchedHtml = websiteCode.html
  const patchedScripts = {}

  vulnerabilities.forEach((vulnerability) => {
    switch (vulnerability.type) {
      case "XSS":
        // Replace inline event handlers with a note
        patchedHtml = patchedHtml.replace(
          /on\w+\s*=\s*["']javascript:[^"']*["']/gi,
          'data-security="event-handler-removed"',
        )
        break

      case "CSRF":
        // Add CSRF token to forms
        patchedHtml = patchedHtml.replace(
          /<form[^>]*method\s*=\s*["']post["'][^>]*>/gi,
          (match) => match + '\n  <input type="hidden" name="_token" value="CSRF_TOKEN_PLACEHOLDER">',
        )
        break

      case "iframe":
        // Add sandbox to iframes
        patchedHtml = patchedHtml.replace(/<iframe([^>]*)>/gi, '<iframe$1 sandbox="allow-scripts allow-same-origin">')
        break

      case "CSP":
        // Add CSP meta tag
        patchedHtml = patchedHtml.replace(
          /<head>/i,
          '<head>\n  <meta http-equiv="Content-Security-Policy" content="default-src \'self\'">',
        )
        break

      case "SRI":
        // Note: In a real extension, you would calculate the SRI hash
        // For this demo, we'll just add a placeholder
        if (vulnerability.code && vulnerability.code.includes("src=")) {
          const srcRegex = /src\s*=\s*["']([^"']+)["']/i
          const srcMatch = srcRegex.exec(vulnerability.code)
          if (srcMatch && srcMatch[1]) {
            const src = srcMatch[1]
            const replacement = vulnerability.code.replace(
              />$/,
              ' integrity="sha384-PLACEHOLDER" crossorigin="anonymous">',
            )
            patchedHtml = patchedHtml.replace(vulnerability.code, replacement)
          }
        }
        break

      case "eval":
      case "Function":
      case "document.write":
      case "innerHTML":
      case "outerHTML":
      case "insertAdjacentHTML":
      case "SQL":
      case "path":
      case "DOM-XSS":
      case "random":
      case "setTimeout":
      case "postMessage":
      case "cookie":
        // For script vulnerabilities, we'll just note them as they require more context-specific fixes
        break
    }
  })

  return {
    html: patchedHtml,
    scripts: patchedScripts,
  }
}

// IMPROVED: Function to display deep scan results
function displayDeepScanResults(vulnerabilities, patchedCode) {
  const resultsContainer = document.getElementById("deepScanResults")
  if (!resultsContainer) return

  if (vulnerabilities.length === 0) {
    resultsContainer.innerHTML = `
      <div class="scan-result safe">
        <h3>✅ No vulnerabilities detected</h3>
        <p>The website appears to be secure based on our scan.</p>
      </div>
    `
    return
  }

  // Count vulnerabilities by severity
  const highCount = vulnerabilities.filter((v) => v.severity === "high").length
  const mediumCount = vulnerabilities.filter((v) => v.severity === "medium").length
  const lowCount = vulnerabilities.filter((v) => v.severity === "low").length

  let resultsHTML = `
    <div class="scan-result ${highCount > 0 ? "critical" : mediumCount > 0 ? "warning" : "low"}">
      <h3>🔍 Vulnerability Scan Results</h3>
      <div class="severity-summary">
        <span class="high-severity">${highCount} High</span>
        <span class="medium-severity">${mediumCount} Medium</span>
        <span class="low-severity">${lowCount} Low</span>
      </div>
    </div>
    <div class="vulnerabilities-list">
  `

  // Add each vulnerability
  vulnerabilities.forEach((vulnerability, index) => {
    resultsHTML += `
      <div class="vulnerability-item ${vulnerability.severity}">
        <div class="vulnerability-header">
          <span class="vulnerability-type">${vulnerability.type}</span>
          <span class="vulnerability-severity ${vulnerability.severity}">${vulnerability.severity}</span>
        </div>
        <div class="vulnerability-description">${vulnerability.description}</div>
        ${vulnerability.location ? `<div class="vulnerability-location">Location: ${vulnerability.location}</div>` : ""}
        <div class="vulnerability-code"><pre>${escapeHtml(vulnerability.code)}</pre></div>
        <div class="vulnerability-fix">
          <strong>Recommended Fix:</strong>
          <pre>${escapeHtml(vulnerability.fix)}</pre>
        </div>
        <button class="patch-button" data-index="${index}">Apply Patch</button>
      </div>
    `
  })

  resultsHTML += `
    </div>
    <div class="action-buttons">
      <button id="patchAllBtn" class="patch-all-button">Patch All Vulnerabilities</button>
      <button id="downloadReportBtn" class="download-report-button">Download Report</button>
    </div>
  `

  resultsContainer.innerHTML = resultsHTML

  // Add event listeners for patch buttons
  document.querySelectorAll(".patch-button").forEach((button) => {
    button.addEventListener("click", () => {
      const index = Number.parseInt(button.getAttribute("data-index"))
      applyPatch(vulnerabilities[index], button)
    })
  })

  // Add event listener for patch all button
  const patchAllBtn = document.getElementById("patchAllBtn")
  if (patchAllBtn) {
    patchAllBtn.addEventListener("click", () => {
      applyAllPatches(vulnerabilities)
    })
  }

  // Add event listener for download report button
  const downloadReportBtn = document.getElementById("downloadReportBtn")
  if (downloadReportBtn) {
    downloadReportBtn.addEventListener("click", () => {
      downloadVulnerabilityReport(vulnerabilities)
    })
  }

  // Helper function to escape HTML
  function escapeHtml(text) {
    if (!text) return ""
    return text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;")
  }
}

// Function to apply a single patch
function applyPatch(vulnerability, button) {
  // Show confirmation dialog
  const confirmPatch = confirm(
    "IMPORTANT: This will modify code only in your current browser view.\n\n" +
      "This patch will NOT change the website for other users or modify the actual website code on the server.\n\n" +
      "The changes are temporary and only affect your current browsing session.\n\n" +
      "Do you want to continue?",
  )

  if (!confirmPatch) {
    return // User cancelled
  }

  // In a real extension, this would modify the page's code
  // For this prototype, we'll just update the UI
  button.textContent = "Patch Applied"
  button.classList.add("patched")
  button.disabled = true

  // Update the parent vulnerability item to show it's patched
  const vulnerabilityItem = button.closest(".vulnerability-item")
  if (vulnerabilityItem) {
    vulnerabilityItem.classList.add("patched")
  }

  // In a real implementation, we would send a message to a content script
  // to actually modify the page's DOM or scripts
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length > 0) {
      chrome.tabs.sendMessage(tabs[0].id, {
        action: "apply_patch",
        vulnerability: vulnerability,
      })
    }
  })
}

// Function to apply all patches
function applyAllPatches(vulnerabilities) {
  // Show confirmation dialog
  const confirmPatch = confirm(
    "IMPORTANT: This will modify code only in your current browser view.\n\n" +
      "These patches will NOT change the website for other users or modify the actual website code on the server.\n\n" +
      "The changes are temporary and only affect your current browsing session.\n\n" +
      "Do you want to apply all patches?",
  )

  if (!confirmPatch) {
    return // User cancelled
  }

  document.querySelectorAll(".patch-button").forEach((button) => {
    if (!button.disabled) {
      // We'll apply directly without triggering click to avoid multiple confirmations
      const index = Number.parseInt(button.getAttribute("data-index"))
      if (!isNaN(index) && vulnerabilities[index]) {
        // Apply patch UI changes
        button.textContent = "Patch Applied"
        button.classList.add("patched")
        button.disabled = true

        const vulnerabilityItem = button.closest(".vulnerability-item")
        if (vulnerabilityItem) {
          vulnerabilityItem.classList.add("patched")
        }

        // Send message to content script
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs.length > 0) {
            chrome.tabs.sendMessage(tabs[0].id, {
              action: "apply_patch",
              vulnerability: vulnerabilities[index],
            })
          }
        })
      }
    }
  })
}

// Function to download vulnerability report
function downloadVulnerabilityReport(vulnerabilities) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs.length) return

    const pageUrl = tabs[0].url
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-")
    const filename = `security-report-${timestamp}.html`

    let reportContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Security Vulnerability Report - ${pageUrl}</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 20px; }
          h1 { color: #333; }
          .url { color: #0066cc; margin-bottom: 20px; }
          .summary { margin: 20px 0; padding: 15px; background: #f5f5f5; border-radius: 5px; }
          .high { color: #d32f2f; }
          .medium { color: #f57c00; }
          .low { color: #388e3c; }
          .vulnerability { margin: 15px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
          .vulnerability-header { display: flex; justify-content: space-between; margin-bottom: 10px; }
          pre { background: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }
          .location { font-style: italic; color: #666; margin-bottom: 10px; }
        </style>
      </head>
      <body>
        <h1>Security Vulnerability Report</h1>
        <div class="url">${pageUrl}</div>
        <div class="summary">
          <h2>Summary</h2>
          <p>Scan completed on: ${new Date().toLocaleString()}</p>
          <p>Total vulnerabilities found: ${vulnerabilities.length}</p>
          <p>
            <span class="high">High: ${vulnerabilities.filter((v) => v.severity === "high").length}</span> | 
            <span class="medium">Medium: ${vulnerabilities.filter((v) => v.severity === "medium").length}</span> | 
            <span class="low">Low: ${vulnerabilities.filter((v) => v.severity === "low").length}</span>
          </p>
        </div>
        <h2>Detailed Findings</h2>
    `

    vulnerabilities.forEach((vulnerability) => {
      reportContent += `
        <div class="vulnerability">
          <div class="vulnerability-header">
            <h3>${vulnerability.type}</h3>
            <span class="${vulnerability.severity}">${vulnerability.severity.toUpperCase()}</span>
          </div>
          <p>${vulnerability.description}</p>
          ${vulnerability.location ? `<div class="location">Location: ${vulnerability.location}</div>` : ""}
          <h4>Vulnerable Code:</h4>
          <pre>${escapeHtml(vulnerability.code)}</pre>
          <h4>Recommended Fix:</h4>
          <pre>${escapeHtml(vulnerability.fix)}</pre>
        </div>
      `
    })

    reportContent += `
      </body>
      </html>
    `

    // Create a blob and download it
    const blob = new Blob([reportContent], { type: "text/html" })
    const url = URL.createObjectURL(blob)

    const a = document.createElement("a")
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)

    // Helper function to escape HTML
    function escapeHtml(text) {
      if (!text) return ""
      return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
    }
  })
}

// Add these functions after the downloadVulnerabilityReport function
// Helper function to show loading indicator - Fixed
function showLoading(message = "Loading...") {
  // Create or update loading element
  let loadingElement = document.getElementById("loadingIndicator")

  if (!loadingElement) {
    loadingElement = document.createElement("div")
    loadingElement.id = "loadingIndicator"
    loadingElement.className = "loading-indicator"
    document.body.appendChild(loadingElement)
  }

  // Fixed: Properly set the HTML content and display style
  loadingElement.innerHTML = `
    <div class="loading-spinner"></div>
    <div class="loading-message">${message}</div>
  `
  loadingElement.style.display = "flex" // Make sure it's visible
}

// Function to perform a deep scan of the website - Fixed
function performDeepScan() {
  // Show loading indicator first
  showLoading("Performing deep vulnerability scan...")
  
  const scanResultsContainer = document.getElementById("deepScanResults")
  if (scanResultsContainer) {
    scanResultsContainer.innerHTML = '<div class="loading">Scanning website for vulnerabilities...</div>'
  }

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs.length) {
      hideLoading()
      showError("No active tab found.")
      return
    }

    // Execute script to get all website code
    chrome.scripting
      .executeScript({
        target: { tabId: tabs[0].id },
        function: getWebsiteCode,
      })
      .then((results) => {
        if (!results || !results[0] || !results[0].result) {
          hideLoading()
          showError("Could not retrieve website code.")
          return
        }

        const websiteCode = results[0].result
        debugLog("Retrieved website code:", websiteCode)

        // Perform deep vulnerability scan
        const vulnerabilities = improvedDeepVulnerabilityScan(websiteCode)
        lastScanResults = vulnerabilities

        debugLog("Vulnerabilities found:", vulnerabilities)

        // Generate patches for found vulnerabilities
        const patchedCode = suggestPatch(websiteCode, vulnerabilities)

        // Display results
        displayDeepScanResults(vulnerabilities, patchedCode)
        
        // Hide loading indicator
        hideLoading()

        // Update statistics
        chrome.storage.local.get(["deepScanCount"], (data) => {
          const newCount = (data.deepScanCount || 0) + 1
          chrome.storage.local.set({ deepScanCount: newCount })
        })
      })
      .catch((error) => {
        hideLoading()
        console.error("Deep Scan Error:", error)
        showError(`Error performing deep scan: ${error.message}`)
      })
  })
}

// Function to generate a comprehensive website report - Fixed
function generateWebsiteReport() {
  showLoading("Generating website report...")

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs.length) {
      hideLoading()
      showError("No active tab found.")
      return
    }

    const tabUrl = tabs[0].url
    const tabId = tabs[0].id

    // Execute script to gather website information
    chrome.scripting
      .executeScript({
        target: { tabId: tabId },
        function: gatherWebsiteInformation,
      })
      .then((results) => {
        if (!results || !results[0] || !results[0].result) {
          hideLoading()
          showError("Could not retrieve website information.")
          return
        }

        const websiteInfo = results[0].result
        debugLog("Website information gathered:", websiteInfo)

        // Create a timeout promise to handle message port closing
        const timeoutPromise = new Promise((_, reject) => {
          setTimeout(() => reject(new Error("Headers request timed out")), 5000)
        })

        // Get additional information from headers with timeout
        Promise.race([
          new Promise((resolve) => {
            chrome.runtime.sendMessage(
              {
                action: "get_website_headers",
                url: tabUrl,
              },
              (headerResponse) => {
                if (chrome.runtime.lastError) {
                  debugLog("Error getting headers:", chrome.runtime.lastError)
                  // Instead of showing error, resolve with empty headers
                  resolve({ headers: {} })
                } else {
                  resolve(headerResponse || { headers: {} })
                }
              },
            )
          }),
          timeoutPromise,
        ])
          .then((headerResponse) => {
            hideLoading()

            // Combine all information
            const fullReport = {
              url: tabUrl,
              title: tabs[0].title,
              websiteInfo: websiteInfo,
              headers: headerResponse?.headers || {},
              timestamp: new Date().toISOString(),
            }

            // Display the report
            displayWebsiteReport(fullReport)

            // Save report to history
            saveReportToHistory(fullReport)
          })
          .catch((error) => {
            hideLoading()
            debugLog("Headers error:", error)

            // Continue with report generation even without headers
            const fullReport = {
              url: tabUrl,
              title: tabs[0].title,
              websiteInfo: websiteInfo,
              headers: {}, // Empty headers
              timestamp: new Date().toISOString(),
            }

            // Show a toast notification about missing headers
            showToast("Could not retrieve HTTP headers, generating report with limited information", "warning")

            // Display the report anyway
            displayWebsiteReport(fullReport)

            // Save report to history
            saveReportToHistory(fullReport)
          })
      })
      .catch((error) => {
        hideLoading()
        console.error("Website Report Error:", error)
        showError(`Error generating report: ${error.message}`)
      })
  })
}

// Function to analyze site safety - Fixed
function analyzeSite() {
  showLoading("Analyzing site...")

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs.length) {
      hideLoading()
      showError("No active tab found.")
      return
    }

    chrome.runtime.sendMessage({ action: "analyze_site", url: tabs[0].url }, (response) => {
      hideLoading()

      if (chrome.runtime.lastError) {
        debugLog("Analysis Error:", chrome.runtime.lastError)
        showError(`Error analyzing site: ${chrome.runtime.lastError.message}`)
        return
      }

      if (!response || !response.result) {
        showError("Error analyzing site. Please try again.")
        return
      }

      updateScanResult(response.result)
      updateStoredStatistics(response.result)
    })
  })
}

// Add this to the document to ensure styles are applied
document.addEventListener("DOMContentLoaded", function() {
  document.head.appendChild(style);
});
// Function to generate a comprehensive website report
function generateWebsiteReport() {
  showLoading("Generating website report...")

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs.length) {
      hideLoading()
      showError("No active tab found.")
      return
    }

    const tabUrl = tabs[0].url
    const tabId = tabs[0].id

    // Execute script to gather website information
    chrome.scripting
      .executeScript({
        target: { tabId: tabId },
        function: gatherWebsiteInformation,
      })
      .then((results) => {
        if (!results || !results[0] || !results[0].result) {
          hideLoading()
          showError("Could not retrieve website information.")
          return
        }

        const websiteInfo = results[0].result
        debugLog("Website information gathered:", websiteInfo)

        // Create a timeout promise to handle message port closing
        const timeoutPromise = new Promise((_, reject) => {
          setTimeout(() => reject(new Error("Headers request timed out")), 5000)
        })

        // Get additional information from headers with timeout
        Promise.race([
          new Promise((resolve) => {
            chrome.runtime.sendMessage(
              {
                action: "get_website_headers",
                url: tabUrl,
              },
              (headerResponse) => {
                if (chrome.runtime.lastError) {
                  debugLog("Error getting headers:", chrome.runtime.lastError)
                  // Instead of showing error, resolve with empty headers
                  resolve({ headers: {} })
                } else {
                  resolve(headerResponse || { headers: {} })
                }
              },
            )
          }),
          timeoutPromise,
        ])
          .then((headerResponse) => {
            hideLoading()

            // Combine all information
            const fullReport = {
              url: tabUrl,
              title: tabs[0].title,
              websiteInfo: websiteInfo,
              headers: headerResponse?.headers || {},
              timestamp: new Date().toISOString(),
            }

            // Display the report
            displayWebsiteReport(fullReport)

            // Save report to history
            saveReportToHistory(fullReport)
          })
          .catch((error) => {
            hideLoading()
            debugLog("Headers error:", error)

            // Continue with report generation even without headers
            const fullReport = {
              url: tabUrl,
              title: tabs[0].title,
              websiteInfo: websiteInfo,
              headers: {}, // Empty headers
              timestamp: new Date().toISOString(),
            }

            // Show a toast notification about missing headers
            showToast("Could not retrieve HTTP headers, generating report with limited information", "warning")

            // Display the report anyway
            displayWebsiteReport(fullReport)

            // Save report to history
            saveReportToHistory(fullReport)
          })
      })
      .catch((error) => {
        hideLoading()
        console.error("Website Report Error:", error)
        showError(`Error generating report: ${error.message}`)
      })
  })
}

// Function to gather website information
function gatherWebsiteInformation() {
  try {
    // Basic page information
    const pageInfo = {
      title: document.title,
      description: document.querySelector('meta[name="description"]')?.content || "",
      keywords: document.querySelector('meta[name="keywords"]')?.content || "",
      author: document.querySelector('meta[name="author"]')?.content || "",
      viewport: document.querySelector('meta[name="viewport"]')?.content || "",
      charset: document.characterSet,
      doctype: document.doctype ? document.doctype.name : "No DOCTYPE",
      domain: document.domain,
      lastModified: document.lastModified,
      referrer: document.referrer,
      cookiesEnabled: navigator.cookieEnabled,
    }

    // Count elements
    const elementCounts = {
      totalElements: document.getElementsByTagName("*").length,
      images: document.getElementsByTagName("img").length,
      links: document.getElementsByTagName("a").length,
      forms: document.getElementsByTagName("form").length,
      scripts: document.getElementsByTagName("script").length,
      iframes: document.getElementsByTagName("iframe").length,
      inputs: document.getElementsByTagName("input").length,
    }

    // External resources
    const externalResources = {
      scripts: [],
      stylesheets: [],
      images: [],
      fonts: [],
      videos: [],
      audios: [],
    }

    // Get external scripts
    document.querySelectorAll("script[src]").forEach((script) => {
      externalResources.scripts.push({
        src: script.src,
        async: script.async,
        defer: script.defer,
        type: script.type || "text/javascript",
        integrity: script.integrity || null,
      })
    })

    // Get stylesheets
    document.querySelectorAll('link[rel="stylesheet"]').forEach((link) => {
      externalResources.stylesheets.push({
        href: link.href,
        media: link.media || "all",
        integrity: link.integrity || null,
      })
    })

    // Get images (limit to first 20 to avoid excessive data)
    document.querySelectorAll("img").forEach((img, index) => {
      if (index < 20) {
        externalResources.images.push({
          src: img.src,
          alt: img.alt || "",
          width: img.width,
          height: img.height,
          loading: img.loading || "auto",
        })
      }
    })

    // Get fonts
    document.querySelectorAll('link[rel="preload"][as="font"]').forEach((font) => {
      externalResources.fonts.push({
        href: font.href,
        type: font.type || "",
      })
    })

    // Get videos
    document.querySelectorAll("video").forEach((video) => {
      const sources = Array.from(video.querySelectorAll("source")).map((source) => ({
        src: source.src,
        type: source.type,
      }))

      externalResources.videos.push({
        sources: sources,
        controls: video.controls,
        autoplay: video.autoplay,
        loop: video.loop,
        muted: video.muted,
      })
    })

    // Get audios
    document.querySelectorAll("audio").forEach((audio) => {
      const sources = Array.from(audio.querySelectorAll("source")).map((source) => ({
        src: source.src,
        type: source.type,
      }))

      externalResources.audios.push({
        sources: sources,
        controls: audio.controls,
        autoplay: audio.autoplay,
        loop: audio.loop,
        muted: audio.muted,
      })
    })

    // Technologies detection (basic)
    const technologies = {
      frameworks: [],
      libraries: [],
      analytics: [],
      advertising: [],
      cms: null,
    }

    // Check for common frameworks and libraries
    if (window.React || document.querySelector("[data-reactroot]")) technologies.frameworks.push("React")
    if (window.angular || document.querySelector("[ng-app]")) technologies.frameworks.push("Angular")
    if (window.Vue) technologies.frameworks.push("Vue.js")
    if (window.jQuery || window.$) technologies.libraries.push("jQuery")
    if (window.bootstrap) technologies.libraries.push("Bootstrap")
    if (window.tailwind) technologies.libraries.push("Tailwind CSS")

    // Check for analytics
    if (window.ga || window.gtag || window.dataLayer) technologies.analytics.push("Google Analytics")
    if (window._paq) technologies.analytics.push("Matomo/Piwik")

    // Check for advertising
    if (window.googletag) technologies.advertising.push("Google Ads")
    if (document.querySelector('script[src*="pagead2.googlesyndication.com"]'))
      technologies.advertising.push("Google AdSense")

    // Check for CMS
    if (document.querySelector('meta[name="generator"][content*="WordPress"]')) technologies.cms = "WordPress"
    if (document.querySelector('meta[name="generator"][content*="Drupal"]')) technologies.cms = "Drupal"
    if (document.querySelector('meta[name="generator"][content*="Joomla"]')) technologies.cms = "Joomla"
    if (document.querySelector('meta[name="generator"][content*="Shopify"]')) technologies.cms = "Shopify"
    if (document.querySelector('meta[name="generator"][content*="Wix"]')) technologies.cms = "Wix"

    // Performance metrics (if available)
    let performance = {}
    if (window.performance) {
      const timing = window.performance.timing
      if (timing) {
        performance = {
          loadTime: timing.loadEventEnd - timing.navigationStart,
          domContentLoaded: timing.domContentLoadedEventEnd - timing.navigationStart,
          firstPaint: timing.responseEnd - timing.navigationStart,
          dns: timing.domainLookupEnd - timing.domainLookupStart,
          tcp: timing.connectEnd - timing.connectStart,
          ttfb: timing.responseStart - timing.requestStart,
          domInteractive: timing.domInteractive - timing.navigationStart,
        }
      }

      // Get resource timing information
      if (window.performance.getEntriesByType) {
        const resources = window.performance.getEntriesByType("resource")
        if (resources && resources.length) {
          performance.resourceCount = resources.length
          performance.totalResourceSize = resources.reduce((total, resource) => {
            return total + (resource.transferSize || 0)
          }, 0)
        }
      }
    }

    // Security information
    const security = {
      https: window.location.protocol === "https:",
      contentSecurityPolicy: !!document.querySelector('meta[http-equiv="Content-Security-Policy"]'),
      xFrameOptions: false, // Will be filled from headers
      strictTransportSecurity: false, // Will be filled from headers
      cookieFlags: {
        secure: false,
        httpOnly: false,
        sameSite: null,
      },
    }

    // Check for cookies with secure flags (limited browser access)
    document.cookie.split(";").forEach((cookie) => {
      if (cookie.trim().toLowerCase().includes("secure")) security.cookieFlags.secure = true
      // Note: httpOnly and SameSite can't be detected from JavaScript
    })

    // Accessibility check (basic)
    const accessibility = {
      hasAltText: true,
      hasAriaLabels: document.querySelectorAll("[aria-label]").length > 0,
      hasLang: !!document.documentElement.lang,
      hasSkipLinks: !!document.querySelector('a[href="#content"], a[href="#main"]'),
      colorContrast: "Not checked", // Would require more complex analysis
    }

    // Check if all images have alt text
    document.querySelectorAll("img").forEach((img) => {
      if (!img.alt && !img.getAttribute("role") === "presentation") {
        accessibility.hasAltText = false
      }
    })

    // Mobile friendliness (basic check)
    const mobileFriendliness = {
      hasViewport: !!document.querySelector('meta[name="viewport"]'),
      usesMediaQueries: false,
      hasTouchEvents: false,
    }

    // Check for media queries
    const styleSheets = document.styleSheets
    try {
      for (let i = 0; i < styleSheets.length; i++) {
        const rules = styleSheets[i].cssRules || styleSheets[i].rules
        if (rules) {
          for (let j = 0; j < rules.length; j++) {
            if (rules[j].type === CSSRule.MEDIA_RULE) {
              mobileFriendliness.usesMediaQueries = true
              break
            }
          }
        }
        if (mobileFriendliness.usesMediaQueries) break
      }
    } catch (e) {
      // CORS may prevent accessing cssRules
      console.error("Could not access CSS rules:", e)
    }

    // Check for touch event listeners
    mobileFriendliness.hasTouchEvents =
      "ontouchstart" in window || navigator.maxTouchPoints > 0 || navigator.msMaxTouchPoints > 0

    // Combine all information
    return {
      pageInfo,
      elementCounts,
      externalResources,
      technologies,
      performance,
      security,
      accessibility,
      mobileFriendliness,
      userAgent: navigator.userAgent,
    }
  } catch (error) {
    console.error("Error in gatherWebsiteInformation:", error)
    return { error: error.message }
  }
}

// Function to display the website report
function displayWebsiteReport(report) {
  const reportContainer = document.getElementById("websiteReportContainer")
  if (!reportContainer) {
    // Create container if it doesn't exist
    const container = document.createElement("div")
    container.id = "websiteReportContainer"
    container.className = "website-report-container"
    document.body.appendChild(container)
  }

  const container = document.getElementById("websiteReportContainer")

  // Format the report
  const reportHTML = `
    <div class="website-report">
      <div class="report-header">
        <h2>Website Report: ${report.title}</h2>
        <div class="report-url">${report.url}</div>
        <div class="report-timestamp">Generated on: ${new Date(report.timestamp).toLocaleString()}</div>
      </div>
      
      <div class="report-section">
        <h3>Overview</h3>
        <div class="report-grid">
          <div class="report-item">
            <div class="item-label">Title</div>
            <div class="item-value">${report.websiteInfo.pageInfo.title || "N/A"}</div>
          </div>
          <div class="report-item">
            <div class="item-label">Description</div>
            <div class="item-value">${report.websiteInfo.pageInfo.description || "N/A"}</div>
          </div>
          <div class="report-item">
            <div class="item-label">Domain</div>
            <div class="item-value">${report.websiteInfo.pageInfo.domain || "N/A"}</div>
          </div>
          <div class="report-item">
            <div class="item-label">Last Modified</div>
            <div class="item-value">${report.websiteInfo.pageInfo.lastModified || "N/A"}</div>
          </div>
          <div class="report-item">
            <div class="item-label">Charset</div>
            <div class="item-value">${report.websiteInfo.pageInfo.charset || "N/A"}</div>
          </div>
          <div class="report-item">
            <div class="item-label">Doctype</div>
            <div class="item-value">${report.websiteInfo.pageInfo.doctype || "N/A"}</div>
          </div>
        </div>
      </div>
      
      <div class="report-section">
        <h3>Element Counts</h3>
        <div class="report-grid">
          <div class="report-item">
            <div class="item-label">Total Elements</div>
            <div class="item-value">${report.websiteInfo.elementCounts.totalElements}</div>
          </div>
          <div class="report-item">
            <div class="item-label">Images</div>
            <div class="item-value">${report.websiteInfo.elementCounts.images}</div>
          </div>
          <div class="report-item">
            <div class="item-label">Links</div>
            <div class="item-value">${report.websiteInfo.elementCounts.links}</div>
          </div>
          <div class="report-item">
            <div class="item-label">Forms</div>
            <div class="item-value">${report.websiteInfo.elementCounts.forms}</div>
          </div>
          <div class="report-item">
            <div class="item-label">Scripts</div>
            <div class="item-value">${report.websiteInfo.elementCounts.scripts}</div>
          </div>
          <div class="report-item">
            <div class="item-label">iframes</div>
            <div class="item-value">${report.websiteInfo.elementCounts.iframes}</div>
          </div>
        </div>
      </div>
      
      <div class="report-section">
        <h3>Technologies</h3>
        <div class="report-grid">
          <div class="report-item">
            <div class="item-label">Frameworks</div>
            <div class="item-value">${report.websiteInfo.technologies.frameworks.length ? report.websiteInfo.technologies.frameworks.join(", ") : "None detected"}</div>
          </div>
          <div class="report-item">
            <div class="item-label">Libraries</div>
            <div class="item-value">${report.websiteInfo.technologies.libraries.length ? report.websiteInfo.technologies.libraries.join(", ") : "None detected"}</div>
          </div>
          <div class="report-item">
            <div class="item-label">Analytics</div>
            <div class="item-value">${report.websiteInfo.technologies.analytics.length ? report.websiteInfo.technologies.analytics.join(", ") : "None detected"}</div>
          </div>
          <div class="report-item">
            <div class="item-label">Advertising</div>
            <div class="item-value">${report.websiteInfo.technologies.advertising.length ? report.websiteInfo.technologies.advertising.join(", ") : "None detected"}</div>
          </div>
          <div class="report-item">
            <div class="item-label">CMS</div>
            <div class="item-value">${report.websiteInfo.technologies.cms || "None detected"}</div>
          </div>
        </div>
      </div>
      
      <div class="report-section">
        <h3>Security</h3>
        <div class="report-grid">
          <div class="report-item">
            <div class="item-label">HTTPS</div>
            <div class="item-value ${report.websiteInfo.security.https ? "secure" : "insecure"}">${report.websiteInfo.security.https ? "Yes" : "No"}</div>
          </div>
          <div class="report-item">
            <div class="item-label">Content Security Policy</div>
            <div class="item-value ${report.websiteInfo.security.contentSecurityPolicy ? "secure" : "insecure"}">${report.websiteInfo.security.contentSecurityPolicy ? "Yes" : "No"}</div>
          </div>
          <div class="report-item">
            <div class="item-label">X-Frame-Options</div>
            <div class="item-value ${report.headers && report.headers["x-frame-options"] ? "secure" : "insecure"}">${report.headers && report.headers["x-frame-options"] ? report.headers["x-frame-options"] : "No"}</div>
          </div>
          <div class="report-item">
            <div class="item-label">Strict-Transport-Security</div>
            <div class="item-value ${report.headers && report.headers["strict-transport-security"] ? "secure" : "insecure"}">${report.headers && report.headers["strict-transport-security"] ? "Yes" : "No"}</div>
          </div>
          <div class="report-item">
            <div class="item-label">X-Content-Type-Options</div>
            <div class="item-value ${report.headers && report.headers["x-content-type-options"] ? "secure" : "insecure"}">${report.headers && report.headers["x-content-type-options"] ? report.headers["x-content-type-options"] : "No"}</div>
          </div>
          <div class="report-item">
            <div class="item-label">Referrer-Policy</div>
            <div class="item-value">${report.headers && report.headers["referrer-policy"] ? report.headers["referrer-policy"] : "Not set"}</div>
          </div>
        </div>
      </div>
      
      <div class="report-section">
        <h3>Performance</h3>
        <div class="report-grid">
          ${
            report.websiteInfo.performance.loadTime
              ? `
          <div class="report-item">
            <div class="item-label">Load Time</div>
            <div class="item-value">${report.websiteInfo.performance.loadTime}ms</div>
          </div>
          <div class="report-item">
            <div class="item-label">DOM Content Loaded</div>
            <div class="item-value">${report.websiteInfo.performance.domContentLoaded}ms</div>
          </div>
          <div class="report-item">
            <div class="item-label">First Paint</div>
            <div class="item-value">${report.websiteInfo.performance.firstPaint}ms</div>
          </div>
          <div class="report-item">
            <div class="item-label">Time to First Byte</div>
            <div class="item-value">${report.websiteInfo.performance.ttfb}ms</div>
          </div>
          `
              : `
          <div class="report-item full-width">
            <div class="item-value">Performance metrics not available</div>
          </div>
          `
          }
        </div>
      </div>
      
      <div class="report-section">
        <h3>Accessibility</h3>
        <div class="report-grid">
          <div class="report-item">
            <div class="item-label">Images have Alt Text</div>
            <div class="item-value ${report.websiteInfo.accessibility.hasAltText ? "secure" : "insecure"}">${report.websiteInfo.accessibility.hasAltText ? "Yes" : "No"}</div>
          </div>
          <div class="report-item">
            <div class="item-label">ARIA Labels</div>
            <div class="item-value ${report.websiteInfo.accessibility.hasAriaLabels ? "secure" : "insecure"}">${report.websiteInfo.accessibility.hasAriaLabels ? "Yes" : "No"}</div>
          </div>
          <div class="report-item">
            <div class="item-label">Language Attribute</div>
            <div class="item-value ${report.websiteInfo.accessibility.hasLang ? "secure" : "insecure"}">${report.websiteInfo.accessibility.hasLang ? "Yes" : "No"}</div>
          </div>
          <div class="report-item">
            <div class="item-label">Skip Links</div>
            <div class="item-value ${report.websiteInfo.accessibility.hasSkipLinks ? "secure" : "insecure"}">${report.websiteInfo.accessibility.hasSkipLinks ? "Yes" : "No"}</div>
          </div>
        </div>
      </div>
      
      <div class="report-section">
        <h3>Mobile Friendliness</h3>
        <div class="report-grid">
          <div class="report-item">
            <div class="item-label">Viewport Meta Tag</div>
            <div class="item-value ${report.websiteInfo.mobileFriendliness.hasViewport ? "secure" : "insecure"}">${report.websiteInfo.mobileFriendliness.hasViewport ? "Yes" : "No"}</div>
          </div>
          <div class="report-item">
            <div class="item-label">Media Queries</div>
            <div class="item-value ${report.websiteInfo.mobileFriendliness.usesMediaQueries ? "secure" : "insecure"}">${report.websiteInfo.mobileFriendliness.usesMediaQueries ? "Yes" : "No"}</div>
          </div>
          <div class="report-item">
            <div class="item-label">Touch Events</div>
            <div class="item-value ${report.websiteInfo.mobileFriendliness.hasTouchEvents ? "secure" : "insecure"}">${report.websiteInfo.mobileFriendliness.hasTouchEvents ? "Yes" : "No"}</div>
          </div>
        </div>
      </div>
      
      <div class="report-section">
        <h3>External Resources</h3>
        <div class="collapsible-content">
          <div class="collapsible-header">Scripts (${report.websiteInfo.externalResources.scripts.length})</div>
          <div class="collapsible-body">
            ${
              report.websiteInfo.externalResources.scripts.length
                ? report.websiteInfo.externalResources.scripts
                    .map(
                      (script) =>
                        `<div class="resource-item">
                  <div class="resource-url">${script.src}</div>
                  <div class="resource-meta">
                    ${script.async ? '<span class="tag">async</span>' : ""}
                    ${script.defer ? '<span class="tag">defer</span>' : ""}
                    ${script.integrity ? '<span class="tag secure">SRI</span>' : '<span class="tag insecure">No SRI</span>'}
                  </div>
                </div>`,
                    )
                    .join("")
                : '<div class="no-resources">No external scripts found</div>'
            }
          </div>
        </div>
        
        <div class="collapsible-content">
          <div class="collapsible-header">Stylesheets (${report.websiteInfo.externalResources.stylesheets.length})</div>
          <div class="collapsible-body">
            ${
              report.websiteInfo.externalResources.stylesheets.length
                ? report.websiteInfo.externalResources.stylesheets
                    .map(
                      (stylesheet) =>
                        `<div class="resource-item">
                  <div class="resource-url">${stylesheet.href}</div>
                  <div class="resource-meta">
                    <span class="tag">${stylesheet.media}</span>
                    ${stylesheet.integrity ? '<span class="tag secure">SRI</span>' : '<span class="tag insecure">No SRI</span>'}
                  </div>
                </div>`,
                    )
                    .join("")
                : '<div class="no-resources">No external stylesheets found</div>'
            }
          </div>
        </div>
      </div>
      
      <div class="report-actions">
        <button id="downloadReportBtn" class="download-report-button">Download Full Report</button>
        <button id="closeReportBtn" class="close-report-button">Close Report</button>
      </div>
    </div>
  `

  container.innerHTML = reportHTML
  container.style.display = "block"

  // Add event listeners for collapsible sections
  document.querySelectorAll(".collapsible-header").forEach((header) => {
    header.addEventListener("click", () => {
      header.classList.toggle("active")
      const body = header.nextElementSibling
      body.style.display = body.style.display === "block" ? "none" : "block"
    })
  })

  // Add event listener for download button
  document.getElementById("downloadReportBtn").addEventListener("click", () => {
    downloadFullReport(report)
  })

  // Add event listener for close button
  document.getElementById("closeReportBtn").addEventListener("click", () => {
    container.style.display = "none"
  })
}

// Function to download the full report
function downloadFullReport(report) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-")
  const filename = `website-report-${extractDomain(report.url)}-${timestamp}.html`

  // Create a more detailed HTML report
  const reportContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Website Report - ${report.title}</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; color: #333; line-height: 1.6; }
        h1 { color: #2196F3; margin-bottom: 5px; }
        h2 { color: #0D47A1; margin-top: 30px; border-bottom: 2px solid #E3F2FD; padding-bottom: 5px; }
        h3 { color: #1976D2; margin-top: 20px; }
        .url { color: #0D47A1; margin-bottom: 20px; font-size: 18px; }
        .timestamp { color: #757575; margin-bottom: 30px; }
        .section { margin: 20px 0; padding: 15px; background: #f5f5f5; border-radius: 5px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px; }
        .item { background: white; padding: 10px; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .label { font-weight: bold; color: #555; }
        .value { margin-top: 5px; }
        .secure { color: #388e3c; }
        .insecure { color: #d32f2f; }
        .warning { color: #f57c00; }
        .resource-list { margin-top: 15px; }
        .resource-item { background: white; padding: 10px; margin-bottom: 10px; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .resource-url { word-break:  border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .resource-url { word-break: break-all; }
        .resource-meta { margin-top: 5px; font-size: 12px; }
        .tag { display: inline-block; background: #E3F2FD; color: #1976D2; padding: 2px 6px; border-radius: 3px; margin-right: 5px; font-size: 11px; }
        .tag.secure { background: #E8F5E9; color: #388e3c; }
        .tag.insecure { background: #FFEBEE; color: #d32f2f; }
        pre { background: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }
        .header-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        .header-table th, .header-table td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
        .header-table th { background-color: #E3F2FD; }
      </style>
    </head>
    <body>
      <h1>Website Report</h1>
      <div class="url">${report.url}</div>
      <div class="timestamp">Generated on: ${new Date(report.timestamp).toLocaleString()}</div>
      
      <h2>Page Information</h2>
      <div class="section">
        <div class="grid">
          <div class="item">
            <div class="label">Title</div>
            <div class="value">${report.websiteInfo.pageInfo.title || "N/A"}</div>
          </div>
          <div class="item">
            <div class="label">Description</div>
            <div class="value">${report.websiteInfo.pageInfo.description || "N/A"}</div>
          </div>
          <div class="item">
            <div class="label">Keywords</div>
            <div class="value">${report.websiteInfo.pageInfo.keywords || "N/A"}</div>
          </div>
          <div class="item">
            <div class="label">Author</div>
            <div class="value">${report.websiteInfo.pageInfo.author || "N/A"}</div>
          </div>
          <div class="item">
            <div class="label">Viewport</div>
            <div class="value">${report.websiteInfo.pageInfo.viewport || "N/A"}</div>
          </div>
          <div class="item">
            <div class="label">Charset</div>
            <div class="value">${report.websiteInfo.pageInfo.charset || "N/A"}</div>
          </div>
          <div class="item">
            <div class="label">Doctype</div>
            <div class="value">${report.websiteInfo.pageInfo.doctype || "N/A"}</div>
          </div>
          <div class="item">
            <div class="label">Domain</div>
            <div class="value">${report.websiteInfo.pageInfo.domain || "N/A"}</div>
          </div>
          <div class="item">
            <div class="label">Last Modified</div>
            <div class="value">${report.websiteInfo.pageInfo.lastModified || "N/A"}</div>
          </div>
          <div class="item">
            <div class="label">Referrer</div>
            <div class="value">${report.websiteInfo.pageInfo.referrer || "N/A"}</div>
          </div>
          <div class="item">
            <div class="label">Cookies Enabled</div>
            <div class="value">${report.websiteInfo.pageInfo.cookiesEnabled ? "Yes" : "No"}</div>
          </div>
        </div>
      </div>
      
      <h2>Element Counts</h2>
      <div class="section">
        <div class="grid">
          <div class="item">
            <div class="label">Total Elements</div>
            <div class="value">${report.websiteInfo.elementCounts.totalElements}</div>
          </div>
          <div class="item">
            <div class="label">Images</div>
            <div class="value">${report.websiteInfo.elementCounts.images}</div>
          </div>
          <div class="item">
            <div class="label">Links</div>
            <div class="value">${report.websiteInfo.elementCounts.links}</div>
          </div>
          <div class="item">
            <div class="label">Forms</div>
            <div class="value">${report.websiteInfo.elementCounts.forms}</div>
          </div>
          <div class="item">
            <div class="label">Scripts</div>
            <div class="value">${report.websiteInfo.elementCounts.scripts}</div>
          </div>
          <div class="item">
            <div class="label">iframes</div>
            <div class="value">${report.websiteInfo.elementCounts.iframes}</div>
          </div>
          <div class="item">
            <div class="label">Inputs</div>
            <div class="value">${report.websiteInfo.elementCounts.inputs}</div>
          </div>
        </div>
      </div>
      
      <h2>Technologies</h2>
      <div class="section">
        <div class="grid">
          <div class="item">
            <div class="label">Frameworks</div>
            <div class="value">${report.websiteInfo.technologies.frameworks.length ? report.websiteInfo.technologies.frameworks.join(", ") : "None detected"}</div>
          </div>
          <div class="item">
            <div class="label">Libraries</div>
            <div class="value">${report.websiteInfo.technologies.libraries.length ? report.websiteInfo.technologies.libraries.join(", ") : "None detected"}</div>
          </div>
          <div class="item">
            <div class="label">Analytics</div>
            <div class="value">${report.websiteInfo.technologies.analytics.length ? report.websiteInfo.technologies.analytics.join(", ") : "None detected"}</div>
          </div>
          <div class="item">
            <div class="label">Advertising</div>
            <div class="value">${report.websiteInfo.technologies.advertising.length ? report.websiteInfo.technologies.advertising.join(", ") : "None detected"}</div>
          </div>
          <div class="item">
            <div class="label">CMS</div>
            <div class="value">${report.websiteInfo.technologies.cms || "None detected"}</div>
          </div>
        </div>
      </div>
      
      <h2>Security</h2>
      <div class="section">
        <div class="grid">
          <div class="item">
            <div class="label">HTTPS</div>
            <div class="value ${report.websiteInfo.security.https ? "secure" : "insecure"}">${report.websiteInfo.security.https ? "Yes" : "No"}</div>
          </div>
          <div class="item">
            <div class="label">Content Security Policy</div>
            <div class="value ${report.websiteInfo.security.contentSecurityPolicy ? "secure" : "insecure"}">${report.websiteInfo.security.contentSecurityPolicy ? "Yes" : "No"}</div>
          </div>
          <div class="item">
            <div class="label">X-Frame-Options</div>
            <div class="value ${report.headers && report.headers["x-frame-options"] ? "secure" : "insecure"}">${report.headers && report.headers["x-frame-options"] ? report.headers["x-frame-options"] : "No"}</div>
          </div>
          <div class="item">
            <div class="label">Strict-Transport-Security</div>
            <div class="value ${report.headers && report.headers["strict-transport-security"] ? "secure" : "insecure"}">${report.headers && report.headers["strict-transport-security"] ? "Yes" : "No"}</div>
          </div>
          <div class="item">
            <div class="label">X-Content-Type-Options</div>
            <div class="value ${report.headers && report.headers["x-content-type-options"] ? "secure" : "insecure"}">${report.headers && report.headers["x-content-type-options"] ? report.headers["x-content-type-options"] : "No"}</div>
          </div>
          <div class="item">
            <div class="label">Referrer-Policy</div>
            <div class="value">${report.headers && report.headers["referrer-policy"] ? report.headers["referrer-policy"] : "Not set"}</div>
          </div>
        </div>
      </div>
      
      <h2>Performance</h2>
      <div class="section">
        <div class="grid">
          ${
            report.websiteInfo.performance.loadTime
              ? `
          <div class="item">
            <div class="label">Load Time</div>
            <div class="value">${report.websiteInfo.performance.loadTime}ms</div>
          </div>
          <div class="item">
            <div class="label">DOM Content Loaded</div>
            <div class="value">${report.websiteInfo.performance.domContentLoaded}ms</div>
          </div>
          <div class="item">
            <div class="label">First Paint</div>
            <div class="value">${report.websiteInfo.performance.firstPaint}ms</div>
          </div>
          <div class="item">
            <div class="label">Time to First Byte</div>
            <div class="value">${report.websiteInfo.performance.ttfb}ms</div>
          </div>
          <div class="item">
            <div class="label">DNS Lookup</div>
            <div class="value">${report.websiteInfo.performance.dns}ms</div>
          </div>
          <div class="item">
            <div class="label">TCP Connection</div>
            <div class="value">${report.websiteInfo.performance.tcp}ms</div>
          </div>
          <div class="item">
            <div class="label">DOM Interactive</div>
            <div class="value">${report.websiteInfo.performance.domInteractive}ms</div>
          </div>
          ${
            report.websiteInfo.performance.resourceCount
              ? `
          <div class="item">
            <div class="label">Resource Count</div>
            <div class="value">${report.websiteInfo.performance.resourceCount}</div>
          </div>
          <div class="item">
            <div class="label">Total Resource Size</div>
            <div class="value">${Math.round(report.websiteInfo.performance.totalResourceSize / 1024)} KB</div>
          </div>
          `
              : ""
          }
          `
              : `
          <div class="item" style="grid-column: 1 / -1;">
            <div class="value">Performance metrics not available</div>
          </div>
          `
          }
        </div>
      </div>
      
      <h2>Accessibility</h2>
      <div class="section">
        <div class="grid">
          <div class="item">
            <div class="label">Images have Alt Text</div>
            <div class="value ${report.websiteInfo.accessibility.hasAltText ? "secure" : "insecure"}">${report.websiteInfo.accessibility.hasAltText ? "Yes" : "No"}</div>
          </div>
          <div class="item">
            <div class="label">ARIA Labels</div>
            <div class="value ${report.websiteInfo.accessibility.hasAriaLabels ? "secure" : "insecure"}">${report.websiteInfo.accessibility.hasAriaLabels ? "Yes" : "No"}</div>
          </div>
          <div class="item">
            <div class="label">Language Attribute</div>
            <div class="value ${report.websiteInfo.accessibility.hasLang ? "secure" : "insecure"}">${report.websiteInfo.accessibility.hasLang ? "Yes" : "No"}</div>
          </div>
          <div class="item">
            <div class="label">Skip Links</div>
            <div class="value ${report.websiteInfo.accessibility.hasSkipLinks ? "secure" : "insecure"}">${report.websiteInfo.accessibility.hasSkipLinks ? "Yes" : "No"}</div>
          </div>
          <div class="item">
            <div class="label">Color Contrast</div>
            <div class="value">${report.websiteInfo.accessibility.colorContrast}</div>
          </div>
        </div>
      </div>
      
      <h2>Mobile Friendliness</h2>
      <div class="section">
        <div class="grid">
          <div class="item">
            <div class="label">Viewport Meta Tag</div>
            <div class="value ${report.websiteInfo.mobileFriendliness.hasViewport ? "secure" : "insecure"}">${report.websiteInfo.mobileFriendliness.hasViewport ? "Yes" : "No"}</div>
          </div>
          <div class="item">
            <div class="label">Media Queries</div>
            <div class="value ${report.websiteInfo.mobileFriendliness.usesMediaQueries ? "secure" : "insecure"}">${report.websiteInfo.mobileFriendliness.usesMediaQueries ? "Yes" : "No"}</div>
          </div>
          <div class="item">
            <div class="label">Touch Events</div>
            <div class="value ${report.websiteInfo.mobileFriendliness.hasTouchEvents ? "secure" : "insecure"}">${report.websiteInfo.mobileFriendliness.hasTouchEvents ? "Yes" : "No"}</div>
          </div>
        </div>
      </div>
      
      <h2>HTTP Headers</h2>
      <div class="section">
        <table class="header-table">
          <tr>
            <th>Header</th>
            <th>Value</th>
          </tr>
          ${Object.entries(report.headers || {})
            .map(
              ([header, value]) =>
                `<tr>
              <td>${header}</td>
              <td>${value}</td>
            </tr>`,
            )
            .join("")}
          ${Object.keys(report.headers || {}).length === 0 ? `<tr><td colspan="2">No headers available</td></tr>` : ""}
        </table>
      </div>
      
      <h2>External Scripts</h2>
      <div class="section">
        <div class="resource-list">
          ${
            report.websiteInfo.externalResources.scripts.length
              ? report.websiteInfo.externalResources.scripts
                  .map(
                    (script) =>
                      `<div class="resource-item">
                <div class="resource-url">${script.src}</div>
                <div class="resource-meta">
                  ${script.async ? '<span class="tag">async</span>' : ""}
                  ${script.defer ? '<span class="tag">defer</span>' : ""}
                  ${script.type !== "text/javascript" ? `<span class="tag">${script.type}</span>` : ""}
                  ${script.integrity ? '<span class="tag secure">SRI</span>' : '<span class="tag insecure">No SRI</span>'}
                </div>
              </div>`,
                  )
                  .join("")
              : "<div>No external scripts found</div>"
          }
        </div>
      </div>
      
      <h2>External Stylesheets</h2>
      <div class="section">
        <div class="resource-list">
          ${
            report.websiteInfo.externalResources.stylesheets.length
              ? report.websiteInfo.externalResources.stylesheets
                  .map(
                    (stylesheet) =>
                      `<div class="resource-item">
                <div class="resource-url">${stylesheet.href}</div>
                <div class="resource-meta">
                  <span class="tag">${stylesheet.media}</span>
                  ${stylesheet.integrity ? '<span class="tag secure">SRI</span>' : '<span class="tag insecure">No SRI</span>'}
                </div>
              </div>`,
                  )
                  .join("")
              : "<div>No external stylesheets found</div>"
          }
        </div>
      </div>
      
      <h2>Images</h2>
      <div class="section">
        <div class="resource-list">
          ${
            report.websiteInfo.externalResources.images.length
              ? report.websiteInfo.externalResources.images
                  .map(
                    (image) =>
                      `<div class="resource-item">
                <div class="resource-url">${image.src}</div>
                <div class="resource-meta">
                  ${image.alt ? `<span class="tag secure">Alt: ${image.alt.substring(0, 30)}${image.alt.length > 30 ? "..." : ""}</span>` : '<span class="tag insecure">No Alt Text</span>'}
                  ${image.width && image.height ? `<span class="tag">${image.width}x${image.height}</span>` : ""}
                  ${image.loading ? `<span class="tag">${image.loading}</span>` : ""}
                </div>
              </div>`,
                  )
                  .join("")
              : "<div>No images found</div>"
          }
        </div>
      </div>
      
      <div style="margin-top: 30px; text-align: center; color: #757575; font-size: 12px;">
        Generated by Security Extension on ${new Date().toLocaleString()}
      </div>
    </body>
    </html>
  `

  // Create a blob and download it
  const blob = new Blob([reportContent], { type: "text/html" })
  const url = URL.createObjectURL(blob)

  const a = document.createElement("a")
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

// Function to save report to history
function saveReportToHistory(report) {
  chrome.storage.local.get(["reportHistory"], (data) => {
    const reportHistory = data.reportHistory || []

    // Create a summary version to save storage space
    const reportSummary = {
      url: report.url,
      title: report.title,
      timestamp: report.timestamp,
      domain: extractDomain(report.url),
      securityScore: calculateSecurityScore(report),
      performanceScore: calculatePerformanceScore(report),
      accessibilityScore: calculateAccessibilityScore(report),
    }

    // Add to history (limit to 20 reports)
    reportHistory.unshift(reportSummary)
    if (reportHistory.length > 20) {
      reportHistory.pop()
    }

    // Save updated history
    chrome.storage.local.set({ reportHistory })
  })
}

// Function to calculate security score
function calculateSecurityScore(report) {
  let score = 0
  let total = 0

  // HTTPS
  if (report.websiteInfo.security.https) {
    score += 20
  }
  total += 20

  // Content Security Policy
  if (report.websiteInfo.security.contentSecurityPolicy) {
    score += 15
  }
  total += 15

  // X-Frame-Options
  if (report.headers && report.headers["x-frame-options"]) {
    score += 10
  }
  total += 10

  // Strict-Transport-Security
  if (report.headers && report.headers["strict-transport-security"]) {
    score += 15
  }
  total += 15

  // X-Content-Type-Options
  if (report.headers && report.headers["x-content-type-options"]) {
    score += 10
  }
  total += 10

  // Referrer-Policy
  if (report.headers && report.headers["referrer-policy"]) {
    score += 10
  }
  total += 10

  // SRI for scripts
  const scriptsWithSRI = report.websiteInfo.externalResources.scripts.filter((s) => s.integrity).length
  const totalScripts = report.websiteInfo.externalResources.scripts.length
  if (totalScripts > 0) {
    score += (scriptsWithSRI / totalScripts) * 10
  }
  total += 10

  // SRI for stylesheets
  const stylesheetsWithSRI = report.websiteInfo.externalResources.stylesheets.filter((s) => s.integrity).length
  const totalStylesheets = report.websiteInfo.externalResources.stylesheets.length
  if (totalStylesheets > 0) {
    score += (stylesheetsWithSRI / totalStylesheets) * 10
  }
  total += 10

  // Calculate percentage
  return Math.round((score / total) * 100)
}

// Function to calculate performance score
function calculatePerformanceScore(report) {
  if (!report.websiteInfo.performance.loadTime) {
    return "N/A"
  }

  let score = 100

  // Load time (deduct points for slow loading)
  if (report.websiteInfo.performance.loadTime > 3000) {
    score -= 20
  } else if (report.websiteInfo.performance.loadTime > 2000) {
    score -= 10
  } else if (report.websiteInfo.performance.loadTime > 1000) {
    score -= 5
  }

  // TTFB (deduct points for slow server response)
  if (report.websiteInfo.performance.ttfb > 600) {
    score -= 20
  } else if (report.websiteInfo.performance.ttfb > 400) {
    score -= 10
  } else if (report.websiteInfo.performance.ttfb > 200) {
    score -= 5
  }

  // Resource count (deduct points for too many resources)
  if (report.websiteInfo.performance.resourceCount > 100) {
    score -= 20
  } else if (report.websiteInfo.performance.resourceCount > 50) {
    score -= 10
  } else if (report.websiteInfo.performance.resourceCount > 30) {
    score -= 5
  }

  // Ensure score is between 0 and 100
  return Math.max(0, Math.min(100, score))
}

// Function to calculate accessibility score
function calculateAccessibilityScore(report) {
  let score = 0
  let total = 0

  // Alt text for images
  if (report.websiteInfo.accessibility.hasAltText) {
    score += 25
  }
  total += 25

  // ARIA labels
  if (report.websiteInfo.accessibility.hasAriaLabels) {
    score += 25
  }
  total += 25

  // Language attribute
  if (report.websiteInfo.accessibility.hasLang) {
    score += 25
  }
  total += 25

  // Skip links
  if (report.websiteInfo.accessibility.hasSkipLinks) {
    score += 25
  }
  total += 25

  // Calculate percentage
  return Math.round((score / total) * 100)
}

// Function to force HTTPS
function enforceHttps(url) {
  if (url.startsWith("http://")) {
    const httpsUrl = url.replace("http://", "https://")
    chrome.tabs.update({ url: httpsUrl })
    debugLog(`Redirected to HTTPS: ${httpsUrl}`)
  }
}

// Define blockedDomains array
const blockedDomains = [
  "example.com",
  "malicious.net",
  "phishing.info",
  // Add more known malicious domains here
]

// Function to block malicious scripts
function blockMaliciousScripts(url) {
  try {
    chrome.webRequest.onBeforeRequest.addListener(
      (details) => {
        if (blockedDomains.some((domain) => details.url.includes(domain))) {
          debugLog("Blocking malicious resource:", details.url)
          return { cancel: true } // Block the request
        }
        return { cancel: false }
      },
      { urls: ["<all_urls>"] }, // Listen to all URLs
      ["blocking"],
    )
  } catch (error) {
    console.error("Error setting up webRequest listener:", error)
  }
}

// Function to inject fake data into forms
function injectFakeData() {
  showLoading("Injecting fake data...")

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs.length) {
      hideLoading()
      showError("No active tab found.")
      return
    }

    chrome.scripting
      .executeScript({
        target: { tabId: tabs[0].id },
        function: fillFakeData,
      })
      .then((results) => {
        hideLoading()

        // Check if we got a result
        if (!results || !results[0]) {
          showError("Error injecting fake data.")
          return
        }

        // Show success message
        showSuccess("Fake data injected successfully!")

        // Update stored statistics for fake data injections
        chrome.storage.local.get(["fakeDataCount"], (data) => {
          const newCount = (data.fakeDataCount || 0) + 1
          chrome.storage.local.set({ fakeDataCount: newCount }, updateStatistics)
        })
      })
      .catch((error) => {
        hideLoading()
        console.error("Script Injection Error:", error)
        showError(`Error injecting fake data: ${error.message}`)
      })
  })
}

// IMPROVED: Function to inject fake form data into webpage
function fillFakeData() {
  try {
    const fakeData = {
      // Personal information
      name: "John Doe",
      firstName: "John",
      lastName: "Doe",
      email: "johndoe@example.com",
      phone: "+1234567890",
      mobile: "+1234567890",
      address: "123 Fake Street",
      address1: "123 Fake Street",
      address2: "Apt 4B",
      city: "New York",
      state: "NY",
      zip: "10001",
      zipCode: "10001",
      postalCode: "10001",
      country: "United States",
      countryCode: "US",

      // Account information
      username: "johndoe",
      password: "SecureP@ssw0rd123!",
      confirmPassword: "SecureP@ssw0rd123!",
      currentPassword: "OldP@ssw0rd",

      // Payment information (NEVER use real data)
      creditCard: "4111111111111111", // Test Visa number
      cardNumber: "4111111111111111",
      cardName: "John Doe",
      cardExpiry: "12/25",
      cardExpiryMonth: "12",
      cardExpiryYear: "25",
      cvv: "123",
      securityCode: "123",

      // Other common fields
      company: "Acme Inc",
      website: "https://example.com",
      bio: "This is a fake bio for testing purposes.",
      comment: "This is a fake comment for testing purposes.",
      message: "This is a fake message for testing purposes.",
      subject: "Test Subject",
      title: "Test Title",
      description: "This is a fake description for testing purposes.",
    }

    // Count how many fields we filled
    let filledCount = 0

    // Get all input, textarea, and select elements
    const formElements = document.querySelectorAll("input, textarea, select")

    formElements.forEach((element) => {
      // Skip hidden, submit, button, and image inputs
      if (
        element.type === "hidden" ||
        element.type === "submit" ||
        element.type === "button" ||
        element.type === "image" ||
        element.type === "file" ||
        element.type === "reset"
      ) {
        return
      }

      // Skip elements that already have a value
      if (element.value && element.value.length > 0) {
        return
      }

      // Get field name and id
      const fieldName = (element.name || "").toLowerCase()
      const fieldId = (element.id || "").toLowerCase()
      const fieldType = element.type.toLowerCase()

      // Try to determine the field type and fill with appropriate data
      if (fieldType === "email" || fieldName.includes("email") || fieldId.includes("email")) {
        element.value = fakeData.email
        filledCount++
      } else if (fieldType === "password" || fieldName.includes("password") || fieldId.includes("password")) {
        // Handle different password fields
        if (fieldName.includes("confirm") || fieldId.includes("confirm")) {
          element.value = fakeData.confirmPassword
        } else if (
          fieldName.includes("current") ||
          fieldName.includes("old") ||
          fieldId.includes("current") ||
          fieldId.includes("old")
        ) {
          element.value = fakeData.currentPassword
        } else {
          element.value = fakeData.password
        }
        filledCount++
      } else if (
        fieldType === "tel" ||
        fieldName.includes("phone") ||
        fieldId.includes("phone") ||
        fieldName.includes("mobile") ||
        fieldId.includes("mobile")
      ) {
        element.value = fakeData.phone
        filledCount++
      } else if (
        fieldName.includes("zip") ||
        fieldId.includes("zip") ||
        fieldName.includes("postal") ||
        fieldId.includes("postal")
      ) {
        element.value = fakeData.zip
        filledCount++
      } else if (fieldName.includes("city") || fieldId.includes("city")) {
        element.value = fakeData.city
        filledCount++
      } else if (
        fieldName.includes("state") ||
        fieldId.includes("state") ||
        fieldName.includes("province") ||
        fieldId.includes("province")
      ) {
        element.value = fakeData.state
        filledCount++
      } else if (fieldName.includes("country") || fieldId.includes("country")) {
        element.value = fakeData.country
        filledCount++
      } else if (
        (fieldName.includes("card") && fieldName.includes("number")) ||
        (fieldId.includes("card") && fieldId.includes("number")) ||
        (fieldId.includes("card") && fieldId.includes("number")) ||
        (fieldId.includes("card") && fieldId.includes("number")) ||
        fieldName.includes("credit") ||
        fieldId.includes("credit")
      ) {
        element.value = fakeData.creditCard
        filledCount++
      } else if (
        fieldName.includes("cvv") ||
        fieldId.includes("cvv") ||
        fieldName.includes("cvc") ||
        fieldId.includes("cvc") ||
        (fieldName.includes("security") && fieldName.includes("code"))
      ) {
        element.value = fakeData.cvv
        filledCount++
      } else if (
        (fieldName.includes("exp") && fieldName.includes("month")) ||
        (fieldId.includes("exp") && fieldId.includes("month"))
      ) {
        element.value = fakeData.cardExpiryMonth
        filledCount++
      } else if (
        (fieldName.includes("exp") && fieldName.includes("year")) ||
        (fieldId.includes("exp") && fieldId.includes("year"))
      ) {
        element.value = fakeData.cardExpiryYear
        filledCount++
      } else if (fieldName.includes("exp") || fieldId.includes("exp")) {
        element.value = fakeData.cardExpiry
        filledCount++
      } else if (fieldType === "text" && (fieldName.includes("name") || fieldId.includes("name"))) {
        // Handle different name fields
        if (fieldName.includes("first") || fieldId.includes("first")) {
          element.value = fakeData.firstName
        } else if (fieldName.includes("last") || fieldId.includes("last")) {
          element.value = fakeData.lastName
        } else if (fieldName.includes("card") || fieldId.includes("card")) {
          element.value = fakeData.cardName
        } else {
          element.value = fakeData.name
        }
        filledCount++
      } else if (fieldName.includes("address") || fieldId.includes("address")) {
        if (
          fieldName.includes("2") ||
          fieldId.includes("2") ||
          fieldName.includes("line2") ||
          fieldId.includes("line2")
        ) {
          element.value = fakeData.address2
        } else {
          element.value = fakeData.address
        }
        filledCount++
      } else if (fieldName.includes("company") || fieldId.includes("company")) {
        element.value = fakeData.company
        filledCount++
      } else if (
        fieldName.includes("website") ||
        fieldId.includes("website") ||
        fieldName.includes("url") ||
        fieldId.includes("url")
      ) {
        element.value = fakeData.website
        filledCount++
      } else if (
        fieldName.includes("username") ||
        fieldId.includes("username") ||
        fieldName.includes("login") ||
        fieldId.includes("login")
      ) {
        element.value = fakeData.username
        filledCount++
      } else if (fieldName.includes("comment") || fieldId.includes("comment")) {
        element.value = fakeData.comment
        filledCount++
      } else if (fieldName.includes("message") || fieldId.includes("message")) {
        element.value = fakeData.message
        filledCount++
      } else if (fieldName.includes("subject") || fieldId.includes("subject")) {
        element.value = fakeData.subject
        filledCount++
      } else if (fieldName.includes("title") || fieldId.includes("title")) {
        element.value = fakeData.title
        filledCount++
      } else if (
        fieldName.includes("description") ||
        fieldId.includes("description") ||
        fieldName.includes("bio") ||
        fieldId.includes("bio")
      ) {
        element.value = fakeData.description
        filledCount++
      } else if (fieldType === "checkbox") {
        // Check boxes for terms, agreements, etc.
        element.checked = true
        filledCount++
      } else if (fieldType === "radio") {
        // Select the first radio button in each group
        const name = element.name
        if (name) {
          const radioGroup = document.querySelectorAll(`input[type="radio"][name="${name}"]`)
          if (radioGroup.length > 0 && !Array.from(radioGroup).some((radio) => radio.checked)) {
            element.checked = true
            filledCount++
          }
        }
      } else if (element.tagName.toLowerCase() === "select") {
        // Select a non-empty option for dropdown menus
        if (element.options.length > 0) {
          // Skip the first option if it's empty (often a placeholder)
          let selectedIndex = 0
          if (element.options[0].value === "" && element.options.length > 1) {
            selectedIndex = 1
          }
          element.selectedIndex = selectedIndex
          filledCount++
        }
      } else if (fieldType === "text" || fieldType === "textarea") {
        // For any other text field, use a generic value
        element.value = "Test value"
        filledCount++
      }
    })

    return { success: true, filledCount: filledCount }
  } catch (error) {
    console.error("Error in fillFakeData:", error)
    return { success: false, error: error.message }
  }
}

// Function to update the scan result display
function updateScanResult(resultText) {
  const resultElement = document.getElementById("scanResult")
  if (!resultElement) return

  resultElement.innerText = resultText

  // Apply color styling based on result type
  if (resultText.toLowerCase().includes("phishing")) {
    resultElement.style.color = "red"
  } else if (resultText.toLowerCase().includes("malicious")) {
    resultElement.style.color = "darkred"
  } else if (resultText.toLowerCase().includes("safe")) {
    resultElement.style.color = "green"
  } else {
    resultElement.style.color = "orange"
  }
}

// New function to update statistics UI directly from data
function updateStatisticsUI(data) {
  const elements = {
    totalScans: document.getElementById("totalScans"),
    safeSites: document.getElementById("safeSites"),
    phishingSites: document.getElementById("phishingSites"),
    fakeDataCount: document.getElementById("fakeDataCount"),
    deepScanCount: document.getElementById("deepScanCount"),
    safePercentage: document.getElementById("safePercentage"),
    phishingPercentage: document.getElementById("phishingPercentage"),
  }

  // Update UI elements if they exist
  if (elements.totalScans) elements.totalScans.innerText = data.totalScans || 0
  if (elements.safeSites) elements.safeSites.innerText = data.safeSites || 0
  if (elements.phishingSites) elements.phishingSites.innerText = data.phishingSites || 0

  // Calculate percentages
  const totalScans = data.totalScans || 0
  const safePercentage = totalScans > 0 ? (((data.safeSites || 0) / totalScans) * 100).toFixed(1) : 0
  const phishingPercentage = totalScans > 0 ? (((data.phishingSites || 0) / totalScans) * 100).toFixed(1) : 0

  if (elements.safePercentage) elements.safePercentage.innerText = safePercentage
  if (elements.phishingPercentage) elements.phishingPercentage.innerText = phishingPercentage
}

// Modify your existing loadStatistics function to call this new function
function loadStatistics() {
  chrome.storage.local.get(["totalScans", "safeSites", "phishingSites", "fakeDataCount", "deepScanCount"], (data) => {
    updateStatisticsUI(data)
  })
}

// Function to update statistics in the UI
function updateStatistics() {
  chrome.storage.local.get(["totalScans", "safeSites", "phishingSites", "fakeDataCount", "deepScanCount"], (data) => {
    const totalScans = data.totalScans || 0
    const safeSites = data.safeSites || 0
    const phishingSites = data.phishingSites || 0
    const fakeDataCount = data.fakeDataCount || 0
    const deepScanCount = data.deepScanCount || 0

    const safePercentage = totalScans > 0 ? ((safeSites / totalScans) * 100).toFixed(1) : 0
    const phishingPercentage = totalScans > 0 ? ((phishingSites / totalScans) * 100).toFixed(1) : 0

    const safePercentageCalc = totalScans > 0 ? ((safeSites / totalScans) * 100).toFixed(1) : 0
    const phishingPercentageCalc = totalScans > 0 ? ((phishingSites / totalScans) * 100).toFixed(1) : 0

    // Update UI elements if they exist
    const elements = {
      keywordScore: document.getElementById("keyword-score"),
      hiddenForms: document.getElementById("hidden-forms"),
      downloadLinks: document.getElementById("download-links"),
      popupScore: document.getElementById("popup-score"),
      riskScore: document.getElementById("risk-score"),
    }

    // Update UI elements if they exist
    const scanResult = {}
    if (elements.keywordScore) elements.keywordScore.innerText = scanResult.keywordScore
    if (elements.hiddenForms) elements.hiddenForms.innerText = scanResult.hiddenFormsCount
    if (elements.downloadLinks) elements.downloadLinks.innerText = scanResult.downloadLinksCount
    if (elements.popupScore) elements.popupScore.innerText = scanResult.popupScore

    // Calculate overall risk score
    if (elements.riskScore) {
      const riskScore =
        scanResult.keywordScore * 2 +
        scanResult.hiddenFormsCount * 3 +
        scanResult.downloadLinksCount * 2 +
        scanResult.popupScore * 1

      elements.riskScore.innerText = riskScore

      // Set color based on risk level
      if (riskScore > 10) {
        elements.riskScore.style.color = "red"
      } else if (riskScore > 5) {
        elements.riskScore.style.color = "orange"
      } else {
        elements.riskScore.style.color = "green"
      }
    }
  })
}

// Function to update stored statistics based on scan results
function updateStoredStatistics(scanResult) {
  chrome.storage.local.get(["totalScans", "safeSites", "phishingSites"], (data) => {
    const totalScans = (data.totalScans || 0) + 1
    let safeSites = data.safeSites || 0
    let phishingSites = data.phishingSites || 0

    if (scanResult.toLowerCase().includes("safe")) {
      safeSites += 1
    } else if (scanResult.toLowerCase().includes("phishing") || scanResult.toLowerCase().includes("malicious")) {
      phishingSites += 1
    }

    chrome.storage.local.set({ totalScans, safeSites, phishingSites }, updateStatistics)
  })
}

// Function to reset statistics
function resetStatistics() {
  chrome.storage.local.set(
    {
      totalScans: 0,
      safeSites: 0,
      phishingSites: 0,
      fakeDataCount: 0,
      deepScanCount: 0,
    },
    () => {
      updateStatistics()
      showSuccess("Statistics reset successfully!")
    },
  )
}

// Function to scan links with VirusTotal API
async function scanLinksWithVirusTotal(links) {
  // Get API key from storage
  return new Promise((resolve) => {
    chrome.storage.local.get(["apiKey"], async (result) => {
      const apiKey = result.apiKey
      if (!apiKey) {
        resolve([{ url: "No API Key", verdict: { malicious: "N/A" } }])
        return
      }

      const results = []
      try {
        // Limit to 5 links to avoid quota issues
        for (const link of links.slice(0, 5)) {
          try {
            const verdict = await scanSingleLink(link, apiKey)
            results.push({ url: link, verdict })
          } catch (error) {
            console.error("Error scanning link:", link, error)
            results.push({
              url: link,
              verdict: { malicious: "Error" },
            })
          }
        }
      } catch (error) {
        console.error("Error in scanLinksWithVirusTotal:", error)
      }

      resolve(results)
    })
  })
}

// Helper function to scan a single link
async function scanSingleLink(link, apiKey) {
  try {
    // Submit URL for scanning
    const response = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": apiKey,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `url=${encodeURIComponent(link)}`,
    })

    if (!response.ok) {
      return { malicious: "Error" }
    }

    const data = await response.json()
    const id = data.data.id

    // Get report
    const reportRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, {
      headers: { "x-apikey": apiKey },
    })

    if (!reportRes.ok) {
      return { malicious: "Error" }
    }

    const reportData = await reportRes.json()
    return reportData.data.attributes.stats
  } catch (error) {
    console.error("Error in scanSingleLink:", error)
    return { malicious: "Error" }
  }
}

// Function to display scan results
function displayScanResults(results) {
  const container = document.getElementById("scanResults")
  if (!container) return

  container.innerHTML = "<h3>Deep Scan Results:</h3>"

  results.forEach((result) => {
    const item = document.createElement("div")
    item.className = "scan-result-item"
    item.innerHTML = `
      <div class="url-container">${truncateUrl(result.url)}</div>
      <div class="verdict ${result.verdict.malicious > 0 ? "malicious" : "safe"}">
        Detected: ${result.verdict.malicious || 0}
      </div>
    `
    container.appendChild(item)
  })
}

// Helper function to truncate long URLs
function truncateUrl(url) {
  try {
    const urlObj = new URL(url)
    return urlObj.hostname + (urlObj.pathname.length > 20 ? urlObj.pathname.substring(0, 20) + "..." : urlObj.pathname)
  } catch (e) {
    return url.length > 30 ? url.substring(0, 30) + "..." : url
  }
}

// Get report count for a URL
function getReportCount(url) {
  return new Promise((resolve) => {
    chrome.storage.local.get(["reportedPages"], (data) => {
      const reportedPages = data.reportedPages || {}
      const domain = extractDomain(url)
      resolve(reportedPages[domain] || 0)
    })
  })
}

// Extract domain from URL
function extractDomain(url) {
  try {
    const urlObj = new URL(url)
    return urlObj.hostname
  } catch (e) {
    return url
  }
}

// Report a suspicious page
function reportSuspiciousPage(url) {
  const domain = extractDomain(url)

  // Show reporting in progress
  const reportBtn = document.getElementById("reportBtn")
  if (reportBtn) {
    const originalText = reportBtn.textContent
    reportBtn.textContent = "Reporting..."
    reportBtn.disabled = true

    // Get current report count
    chrome.storage.local.get(["reportedPages"], (data) => {
      const reportedPages = data.reportedPages || {}
      const currentCount = reportedPages[domain] || 0

      // Increment report count
      reportedPages[domain] = currentCount + 1

      // Save updated report count
      chrome.storage.local.set({ reportedPages }, () => {
        // Show success message with count
        reportBtn.textContent = "Reported!"
        reportBtn.style.backgroundColor = "#4CAF50"

        // Show report count
        showReportCount(domain, reportedPages[domain])

        setTimeout(() => {
          reportBtn.textContent = originalText
          reportBtn.style.backgroundColor = ""
          reportBtn.disabled = false
        }, 2000)
      })
    })
  }
}

// Show report count for current page
function showReportCountForCurrentPage() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0] && tabs[0].url) {
      const domain = extractDomain(tabs[0].url)
      getReportCount(tabs[0].url).then((count) => {
        if (count > 0) {
          showReportCount(domain, count)
        }
      })
    }
  })
}

// Display report count in UI
function showReportCount(domain, count) {
  // Create or update report count element
  let reportCountElement = document.getElementById("reportCount")

  if (!reportCountElement) {
    reportCountElement = document.createElement("div")
    reportCountElement.id = "reportCount"
    reportCountElement.className = "report-count"

    // Insert after the report button
    const reportBtn = document.getElementById("reportBtn")
    if (reportBtn && reportBtn.parentNode) {
      reportBtn.parentNode.insertBefore(reportCountElement, reportBtn.nextSibling)
    }
  }

  reportCountElement.innerHTML = `
    <div class="report-count-info">
      <span class="domain">${domain}</span> has been reported 
      <span class="count">${count}</span> time${count !== 1 ? "s" : ""} by users
    </div>
  `
}

// Function to update popup UI with scan results
function updatePopupUI(scanResult) {
  const elements = {
    keywordScore: document.getElementById("keyword-score"),
    hiddenForms: document.getElementById("hidden-forms"),
    downloadLinks: document.getElementById("download-links"),
    popupScore: document.getElementById("popup-score"),
    riskScore: document.getElementById("risk-score"),
  }

  // Update UI elements if they exist
  if (elements.keywordScore) elements.keywordScore.innerText = scanResult.keywordScore
  if (elements.hiddenForms) elements.hiddenForms.innerText = scanResult.hiddenFormsCount
  if (elements.downloadLinks) elements.downloadLinks.innerText = scanResult.downloadLinksCount
  if (elements.popupScore) elements.popupScore.innerText = scanResult.popupScore

  // Calculate overall risk score
  if (elements.riskScore) {
    const riskScore =
      scanResult.keywordScore * 2 +
      scanResult.hiddenFormsCount * 3 +
      scanResult.downloadLinksCount * 2 +
      scanResult.popupScore * 1

    elements.riskScore.innerText = riskScore

    // Set color based on risk level
    if (riskScore > 10) {
      elements.riskScore.style.color = "red"
    } else if (riskScore > 5) {
      elements.riskScore.style.color = "orange"
    } else {
      elements.riskScore.style.color = "green"
    }
  }
}

// Helper function to update statistics UI directly from data
function updateStatisticsUI(data) {
  const elements = {
    totalScans: document.getElementById("totalScans"),
    safeSites: document.getElementById("safeSites"),
    phishingSites: document.getElementById("phishingSites"),
    fakeDataCount: document.getElementById("fakeDataCount"),
    deepScanCount: document.getElementById("deepScanCount"),
    safePercentage: document.getElementById("safePercentage"),
    phishingPercentage: document.getElementById("phishingPercentage"),
  }

  // Update UI elements if they exist
  if (elements.totalScans) elements.totalScans.innerText = data.totalScans || 0
  if (elements.safeSites) elements.safeSites.innerText = data.safeSites || 0
  if (elements.phishingSites) elements.phishingSites.innerText = data.phishingSites || 0

  // Calculate percentages
  const totalScans = data.totalScans || 0
  const safePercentage = totalScans > 0 ? (((data.safeSites || 0) / totalScans) * 100).toFixed(1) : 0
  const phishingPercentage = totalScans > 0 ? (((data.phishingSites || 0) / totalScans) * 100).toFixed(1) : 0

  if (elements.safePercentage) elements.safePercentage.innerText = safePercentage
  if (elements.phishingPercentage) elements.phishingPercentage.innerText = phishingPercentage
}

// Modify your existing loadStatistics function to call this new function
function loadStatistics() {
  chrome.storage.local.get(["totalScans", "safeSites", "phishingSites", "fakeDataCount", "deepScanCount"], (data) => {
    updateStatisticsUI(data)
  })
}

// Function to load existing statistics on page load
function loadStatistics() {
  updateStatistics()
}

// Helper function to show error messages
function showError(message) {
  const errorElement = document.getElementById("scanResult")
  if (errorElement) {
    errorElement.innerText = message
    errorElement.style.color = "red"
  }

  // Also show in toast if available
  if (typeof showToast === "function") {
    showToast(message, "error")
  }
}

// Helper function to show success messages
function showSuccess(message) {
  const resultElement = document.getElementById("scanResult")
  if (resultElement) {
    resultElement.innerText = message
    resultElement.style.color = "green"
  }

  // Also show in toast if available
  if (typeof showToast === "function") {
    showToast(message, "success")
  }
}

// Helper function to show toast notifications
function showToast(message, type = "info") {
  // Create toast container if it doesn't exist
  let toastContainer = document.getElementById("toast-container")
  if (!toastContainer) {
    toastContainer = document.createElement("div")
    toastContainer.id = "toast-container"
    document.body.appendChild(toastContainer)
  }

  // Create toast element
  const toast = document.createElement("div")
  toast.className = `toast toast-${type}`
  toast.textContent = message

  // Add to container
  toastContainer.appendChild(toast)

  // Remove after 3 seconds
  setTimeout(() => {
    toast.classList.add("toast-hide")
    setTimeout(() => {
      if (toastContainer.contains(toast)) {
        toastContainer.removeChild(toast)
      }
    }, 300)
  }, 3000)
}

// Helper function to show loading indicator
function showLoading(message = "Loading...") {
  // Create or update loading element
  let loadingElement = document.getElementById("loadingIndicator")

  if (!loadingElement) {
    loadingElement = document.createElement("div")
    loadingElement.id = "loadingIndicator"
    loadingElement.className = "loading-indicator"
    document.body.appendChild(loadingElement)
  }

  loadingElement.innerHTML = `
    <div class="loading-spinner"></div>
    <div class="loading-message">${message}</div>
  `

  loadingElement.style.display = "flex"
}

// Helper function to hide loading indicator
function hideLoading() {
  const loadingElement = document.getElementById("loadingIndicator")
  if (loadingElement) {
    loadingElement.style.display = "none"
  }
}

// Add styles for UI elements
const style = document.createElement("style")
style.textContent = `
  .report-count {
    margin-top: 10px;
    padding: 8px;
    background-color: #f5f5f5;
    border-radius: 4px;
    font-size: 13px;
  }
  
  .report-count-info {
    color: #555;
  }
  
  .report-count .domain {
    font-weight: bold;
  }
  
  .report-count .count {
    color: #e53935;
    font-weight: bold;
  }

  /* Deep Scan Results Styles */
  #deepScanResults {
    margin-top: 15px;
  }

  .loading {
    text-align: center;
    padding: 10px;
    color: #666;
  }

  .scan-result {
    padding: 12px;
    border-radius: 4px;
    margin-bottom: 10px;
  }

  .scan-result.safe {
    background-color: #e8f5e9;
    border-left: 4px solid #4caf50;
  }

  .scan-result.warning {
    background-color: #fff8e1;
    border-left: 4px solid #ffc107;
  }

  .scan-result.critical {
    background-color: #ffebee;
    border-left: 4px solid #f44336;
  }

  .severity-summary {
    display: flex;
    gap: 10px;
    margin-top: 8px;
  }

  .high-severity {
    color: #d32f2f;
    font-weight: bold;
  }

  .medium-severity {
    color: #f57c00;
    font-weight: bold;
  }

  .low-severity {
    color: #388e3c;
    font-weight: bold;
  }

  .vulnerabilities-list {
    margin-top: 15px;
  }

  .vulnerability-item {
    border: 1px solid #ddd;
    border-radius: 4px;
    padding: 12px;
    margin-bottom: 10px;
  }

  .vulnerability-item.high {
    border-left: 4px solid #d32f2f;
  }

  .vulnerability-item.medium {
    border-left: 4px solid #f57c00;
  }

  .vulnerability-item.low {
    border-left: 4px solid #388e3c;
  }

  .vulnerability-item.patched {
    background-color: #f1f8e9;
    border-left: 4px solid #4caf50;
  }

  .vulnerability-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
  }

  .vulnerability-type {
    font-weight: bold;
  }

  .vulnerability-severity {
    padding: 3px 8px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: bold;
    text-transform: uppercase;
  }

  .vulnerability-severity.high {
    background-color: #ffebee;
    color: #d32f2f;
  }

  .vulnerability-severity.medium {
    background-color: #fff8e1;
    color: #f57c00;
  }

  .vulnerability-severity.low {
    background-color: #e8f5e9;
    color: #388e3c;
  }

  .vulnerability-description {
    margin-bottom: 8px;
  }
  
  .vulnerability-location {
    font-style: italic;
    color: #666;
    margin-bottom: 8px;
    font-size: 12px;
  }

  .vulnerability-code {
    margin-bottom: 8px;
  }

  .vulnerability-code pre {
    background-color: #f5f5f5;
    padding: 8px;
    border-radius: 4px;
    overflow-x: auto;
    font-size: 12px;
  }

  .vulnerability-fix {
    margin-bottom: 12px;
  }

  .vulnerability-fix pre {
    background-color: #e8f5e9;
    padding: 8px;
    border-radius: 4px;
    overflow-x: auto;
    font-size: 12px;
  }

  .patch-button {
    background-color: #2196f3;
    color: white;
    border: none;
    padding: 6px 12px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 13px;
  }

  .patch-button:hover {
    background-color: #1976d2;
  }

  .patch-button.patched {
    background-color: #4caf50;
  }

  .action-buttons {
    display: flex;
    gap: 10px;
    margin-top: 15px;
  }

  .patch-all-button, .download-report-button {
    flex: 1;
    padding: 8px 16px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-weight: bold;
  }

  .patch-all-button {
    background-color: #2196f3;
    color: white;
  }

  .download-report-button {
    background-color: #4caf50;
    color: white;
  }
  
  /* Loading indicator */
  .loading-indicator {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.5);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    z-index: 9999;
  }
  
  .loading-spinner {
    width: 40px;
    height: 40px;
    border: 4px solid #f3f3f3;
    border-top: 4px solid #3498db;
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }
  
  .loading-message {
    margin-top: 10px;
    color: white;
    font-weight: bold;
  }
  
  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }
  
  /* Toast notifications */
  #toast-container {
    position: fixed;
    bottom: 20px;
    right: 20px;
    z-index: 9999;
  }
  
  .toast {
    padding: 10px 15px;
    margin-bottom: 10px;
    border-radius: 4px;
    color: white;
    opacity: 1;
    transition: opacity 0.3s;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2);
  }
  
  .toast-info {
    background-color: #2196F3;
  }
  
  .toast-success {
    background-color: #4CAF50;
  }
  
  .toast-error {
    background-color: #F44336;
  }
  
  .toast-warning {
    background-color: #FF9800;
  }
  
  .toast-hide {
    opacity: 0;
  }
  
  /* Disabled buttons */
  button.disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
`
style.textContent += `
  /* Website Report Styles */
  .website-report-container {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.8);
    z-index: 9999;
    overflow-y: auto;
    display: none;
  }
  
  .website-report {
    background-color: white;
    margin: 20px auto;
    max-width: 800px;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
  }
  
  .report-header {
    margin-bottom: 20px;
    border-bottom: 2px solid #E3F2FD;
    padding-bottom: 10px;
  }
  
  .report-header h2 {
    color: #2196F3;
    margin-bottom: 5px;
  }
  
  .report-url {
    color: #0D47A1;
    margin-bottom: 5px;
    word-break: break-all;
  }
  
  .report-timestamp {
    color: #757575;
    font-size: 12px;
  }
  
  .report-section {
    margin-bottom: 20px;
    padding: 15px;
    background: #f5f5f5;
    border-radius: 5px;
  }
  
  .report-section h3 {
    color: #1976D2;
    margin-top: 0;
    margin-bottom: 15px;
  }
  
  .report-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 10px;
  }
  
  .report-item {
    background: white;
    padding: 10px;
    border-radius: 4px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
  }
  
  .report-item.full-width {
    grid-column: 1 / -1;
  }
  
  .item-label {
    font-weight: bold;
    color: #555;
    font-size: 12px;
  }
  
  .item-value {
    margin-top: 5px;
  }
  
  .secure {
    color: #388e3c;
  }
  
  .insecure {
    color: #d32f2f;
  }
  
  .warning {
    color: #f57c00;
  }
  
  .collapsible-content {
    margin-bottom: 10px;
  }
  
  .collapsible-header {
    background-color: #E3F2FD;
    color: #1976D2;
    padding: 10px;
    border-radius: 4px;
    cursor: pointer;
    font-weight: bold;
  }
  
  .collapsible-header:hover {
    background-color: #BBDEFB;
  }
  
  .collapsible-header.active {
    border-bottom-left-radius: 0;
    border-bottom-right-radius: 0;
  }
  
  .collapsible-body {
    display: none;
    background-color: white;
    padding: 10px;
    border: 1px solid #E3F2FD;
    border-top: none;
    border-bottom-left-radius: 4px;
    border-bottom-right-radius: 4px;
  }
  
  .resource-item {
    padding: 8px;
    border-bottom: 1px solid #f0f0f0;
  }
  
  .resource-item:last-child {
    border-bottom: none;
  }
  
  .resource-url {
    word-break: break-all;
    font-size: 12px;
  }
  
  .resource-meta {
    margin-top: 5px;
  }
  
  .tag {
    display: inline-block;
    background: #E3F2FD;
    color: #1976D2;
    padding: 2px 6px;
    border-radius: 3px;
    margin-right: 5px;
    font-size: 11px;
  }
  
  .tag.secure {
    background: #E8F5E9;
    color: #388e3c;
  }
  
  .tag.insecure {
    background: #FFEBEE;
    color: #d32f2f;
  }
  
  .no-resources {
    color: #757575;
    font-style: italic;
    padding: 10px 0;
  }
  
  .report-actions {
    display: flex;
    justify-content: space-between;
    margin-top: 20px;
  }
  
  .download-report-button, .close-report-button {
    padding: 10px 20px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-weight: bold;
  }
  
  .download-report-button {
    background-color: #4CAF50;
    color: white;
  }
  
  .close-report-button {
    background-color: #F44336;
    color: white;
  }
`

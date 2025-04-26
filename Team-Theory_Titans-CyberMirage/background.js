// Background script for security extension

// Message handler for all extension communications
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  try {
    // Handle site analysis request
    if (message.action === "analyze_site") {
      handleSiteAnalysis(message.url, sendResponse)
      return true // Keep channel open for async response
    }

    // Handle hover link analysis request
    else if (message.action === "analyze_hover_link") {
      handleHoverAnalysis(message.url, sendResponse)
      return true // Keep channel open for async response
    }

    // Handle website headers request
    else if (message.action === "get_website_headers") {
      fetchWebsiteHeaders(message.url, sendResponse)
      return true // Keep channel open for async response
    }
  } catch (error) {
    console.error("Error in message handler:", error)
    sendResponse({ error: "Internal extension error" })
    return true
  }
})

// Handle full site analysis
function handleSiteAnalysis(url, sendResponse) {
  chrome.storage.local.get(["apiKey"], (result) => {
    const apiKey = result.apiKey

    if (!apiKey) {
      sendResponse({ result: "⚠️ API Key is missing. Please enter it in the settings." })
      return
    }

    analyzeWithVirusTotal(url, apiKey)
      .then((apiResponse) => {
        let resultMessage = `${apiResponse.riskLevel}\n\n`

        if (apiResponse.threatTypes && apiResponse.threatTypes.length > 0) {
          resultMessage += `🔍 Detected Threats:\n• ${apiResponse.threatTypes.join("\n• ")}\n`
        }

        resultMessage += `📊 Risk Score: ${apiResponse.riskScore}`

        // Update statistics based on the risk assessment
        if (apiResponse.isMalicious) {
          updateStoredStatistics("phishing")
        } else if (apiResponse.isSafe) {
          updateStoredStatistics("safe")
        } else {
          updateStoredStatistics("unknown")
        }

        sendResponse({ result: resultMessage })
      })
      .catch((error) => {
        console.error("Error in analysis:", error)
        sendResponse({ result: "⚠️ Error analyzing site. Please try again." })
      })
  })
}

// Handle hover link analysis
function handleHoverAnalysis(url, sendResponse) {
  chrome.storage.local.get(["apiKey"], (result) => {
    const apiKey = result.apiKey

    if (!apiKey) {
      sendResponse({
        isSafe: false,
        isMalicious: false,
        message: "API Key missing",
      })
      return
    }

    // Use a simplified/faster analysis for hover to avoid rate limiting
    quickAnalyzeLink(url, apiKey)
      .then((result) => {
        console.log("Quick analysis result:", result)
        // FIX: Make sure we're sending the complete result object with all properties
        sendResponse({
          isSafe: result.isSafe,
          isMalicious: result.isMalicious,
          message: result.message || result.riskLevel || "Unknown",
        })
      })
      .catch((error) => {
        console.error("Error in hover analysis:", error)
        sendResponse({
          isSafe: false,
          isMalicious: false,
          message: "Analysis error",
        })
      })
  })
}

// Fetch website headers for the report generation
function fetchWebsiteHeaders(url, sendResponse) {
  try {
    fetch(url, { method: "HEAD" })
      .then((response) => {
        const headers = {}
        response.headers.forEach((value, name) => {
          headers[name.toLowerCase()] = value
        })

        sendResponse({ headers: headers })
      })
      .catch((error) => {
        console.error("Error fetching headers:", error)
        sendResponse({ headers: {} })
      })
  } catch (error) {
    console.error("Error in fetchWebsiteHeaders:", error)
    sendResponse({ headers: {} })
  }
}

// Quick analysis function for hover - uses cached results when possible
async function quickAnalyzeLink(url, apiKey) {
  try {
    // Check if we have a cached result for this URL
    const cacheKey = `url_cache_${btoa(url).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}`

    // Try to get from cache first
    const cachedResult = await new Promise((resolve) => {
      chrome.storage.local.get([cacheKey], (result) => {
        if (result[cacheKey] && Date.now() - result[cacheKey].timestamp < 3600000) {
          // 1 hour cache
          resolve(result[cacheKey].data)
        } else {
          resolve(null)
        }
      })
    })

    if (cachedResult) {
      console.log("Using cached result for:", url)
      return cachedResult
    }

    // No cache, do a quick check using the URL report endpoint
    const urlId = btoa(url).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")

    try {
      // Try to get an existing report first (faster)
      const reportResult = await getUrlReport(urlId, apiKey)

      // FIX: Ensure we're returning a properly formatted result
      const formattedResult = {
        isSafe: reportResult.isSafe,
        isMalicious: reportResult.isMalicious,
        message: reportResult.riskLevel || "Unknown",
      }

      // Cache the result
      cacheResult(cacheKey, formattedResult)
      return formattedResult
    } catch (error) {
      // If no existing report, do a quick analysis
      console.log("No existing report, submitting for analysis:", url)
      const analysisResult = await analyzeWithVirusTotal(url, apiKey)

      // FIX: Ensure we're returning a properly formatted result
      const formattedResult = {
        isSafe: analysisResult.isSafe,
        isMalicious: analysisResult.isMalicious,
        message: analysisResult.riskLevel || "Unknown",
      }

      // Cache the result
      cacheResult(cacheKey, formattedResult)
      return formattedResult
    }
  } catch (error) {
    console.error("Quick analysis error:", error)
    return {
      isSafe: false,
      isMalicious: false,
      message: "Error analyzing link",
    }
  }
}

// Cache the analysis result
function cacheResult(key, data) {
  chrome.storage.local.set({
    [key]: {
      data: {
        isSafe: data.isSafe,
        isMalicious: data.isMalicious,
        message: data.riskLevel || data.message || "Unknown",
      },
      timestamp: Date.now(),
    },
  })
}

// VirusTotal Analysis Function
async function analyzeWithVirusTotal(url, apiKey) {
  try {
    const encodedUrl = encodeURIComponent(url)

    // Step 1: Submit URL for scanning
    const submitResponse = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": apiKey,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `url=${encodedUrl}`,
    })

    if (submitResponse.status === 409) {
      // URL already analyzed - try to get the report directly
      console.log("URL already analyzed, fetching existing report")
      const urlId = btoa(url).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
      return await getUrlReport(urlId, apiKey)
    }

    if (!submitResponse.ok) throw new Error(`Submission failed: ${submitResponse.status}`)

    const submitData = await submitResponse.json()
    const analysisId = submitData.data?.id
    if (!analysisId) throw new Error("No analysis ID returned")

    // Step 2: Polling the analysis until it's complete
    let analysisData
    let retries = 10
    while (retries-- > 0) {
      const analysisResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        method: "GET",
        headers: { "x-apikey": apiKey },
      })

      if (!analysisResponse.ok) throw new Error(`Failed to fetch analysis: ${analysisResponse.status}`)
      analysisData = await analysisResponse.json()
      console.log("Analysis Data:", analysisData)

      const status = analysisData.data?.attributes?.status
      if (status === "completed") break

      await new Promise((res) => setTimeout(res, 2000)) // wait 2 seconds between checks
    }

    if (!analysisData || analysisData.data?.attributes?.status !== "completed") {
      throw new Error("Analysis did not complete in time")
    }

    return processAnalysisResults(analysisData)
  } catch (error) {
    console.error("Analysis error:", error)
    return {
      isMalicious: false,
      isSafe: false,
      riskScore: "N/A",
      threatTypes: ["⚠️ Error occurred: " + error.message],
      riskLevel: "❌ Unable to determine risk",
    }
  }
}

// Process the analysis results from VirusTotal
function processAnalysisResults(analysisData) {
  try {
    const stats = analysisData.data?.attributes?.stats || {}
    const results = analysisData.data?.attributes?.results || {}

    console.log("Scan Stats:", stats)
    console.log("Scan Results:", results)

    const threatTypes = new Set()
    let highestSeverityFound = "none" // Track the highest severity found

    // Process each security vendor's results
    for (const engine in results) {
      const result = results[engine]
      if (result.category === "malicious" || result.category === "suspicious") {
        // Add the threat with the engine name for more detail
        threatTypes.add(`${engine}: ${result.result || result.category}`)

        // Update highest severity
        if (result.category === "malicious") {
          highestSeverityFound = "malicious"
        } else if (highestSeverityFound !== "malicious" && result.category === "suspicious") {
          highestSeverityFound = "suspicious"
        }
      }
    }

    const maliciousCount = stats.malicious || 0
    const suspiciousCount = stats.suspicious || 0
    const harmlessCount = stats.harmless || 0
    const undetectedCount = stats.undetected || 0

    // Calculate a weighted risk score
    const totalEngines = maliciousCount + suspiciousCount + harmlessCount + undetectedCount
    const maliciousWeight = 10
    const suspiciousWeight = 5

    // Calculate percentage-based score for more accuracy
    const score =
      totalEngines > 0
        ? Math.round(((maliciousCount * maliciousWeight + suspiciousCount * suspiciousWeight) / totalEngines) * 10)
        : 0

    // Determine risk level based on score and counts
    let riskLevel
    if (maliciousCount >= 3) {
      riskLevel = "☠️ HIGH RISK - MALICIOUS SITE DETECTED"
    } else if (maliciousCount > 0 || suspiciousCount >= 3) {
      riskLevel = "⚠️ MEDIUM RISK - SUSPICIOUS ACTIVITY DETECTED"
    } else if (suspiciousCount > 0) {
      riskLevel = "⚠️ LOW RISK - MINOR SUSPICIOUS SIGNALS"
    } else if (harmlessCount > 5) {
      riskLevel = "✅ SAFE - No threats detected"
    } else {
      riskLevel = "⚠️ UNKNOWN - Insufficient data"
    }

    // More strict safety determination
    // A site is only safe if it has NO malicious or suspicious flags AND has multiple harmless confirmations
    const isSafe = maliciousCount === 0 && suspiciousCount === 0 && harmlessCount > 5

    // A site is malicious if it has ANY malicious flags or multiple suspicious flags
    const isMalicious = maliciousCount > 0 || suspiciousCount >= 3

    // If we have no threats but want to show something
    if (threatTypes.size === 0 && !isSafe) {
      threatTypes.add("No specific threats identified, but insufficient positive signals")
    }

    return {
      isMalicious,
      isSafe,
      riskScore: score,
      threatTypes: [...threatTypes],
      riskLevel,
    }
  } catch (error) {
    console.error("Error processing results:", error)
    return {
      isMalicious: false,
      isSafe: false,
      riskScore: "Error",
      threatTypes: ["Error processing scan results"],
      riskLevel: "❌ Error in risk assessment",
    }
  }
}

// Get an existing URL report when we get a 409 (already analyzed)
async function getUrlReport(urlId, apiKey) {
  try {
    const reportResponse = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      method: "GET",
      headers: { "x-apikey": apiKey },
    })

    if (!reportResponse.ok) {
      throw new Error(`Failed to fetch URL report: ${reportResponse.status}`)
    }

    const reportData = await reportResponse.json()
    console.log("URL Report Data:", reportData)

    // Create a compatible format for our processing function
    const analysisData = {
      data: {
        attributes: {
          stats: reportData.data?.attributes?.last_analysis_stats || {},
          results: reportData.data?.attributes?.last_analysis_results || {},
          status: "completed",
        },
      },
    }

    return processAnalysisResults(analysisData)
  } catch (error) {
    console.error("Error fetching URL report:", error)
    return {
      isMalicious: false,
      isSafe: false,
      riskScore: "N/A",
      threatTypes: ["⚠️ Error retrieving existing report: " + error.message],
      riskLevel: "❌ Unable to determine risk",
    }
  }
}

// Track stats in Chrome Storage
function updateStoredStatistics(siteType) {
  chrome.storage.local.get(["totalScans", "safeSites", "phishingSites", "unknownSites"], (data) => {
    try {
      const updates = {
        totalScans: (Number.parseInt(data.totalScans) || 0) + 1,
        safeSites: Number.parseInt(data.safeSites) || 0,
        phishingSites: Number.parseInt(data.phishingSites) || 0,
        unknownSites: Number.parseInt(data.unknownSites) || 0,
      }

      if (siteType === "safe") updates.safeSites += 1
      else if (siteType === "phishing") updates.phishingSites += 1
      else updates.unknownSites += 1

      chrome.storage.local.set(updates, () => {
        if (chrome.runtime.lastError) {
          console.error("Error updating statistics:", chrome.runtime.lastError)
        } else {
          console.log(`✅ Stats updated: ${siteType}`)

          chrome.runtime.sendMessage({
            type: "STATS_UPDATED",
            data: updates,
          })
        }
      })
    } catch (error) {
      console.error("⚠️ Stats update error:", error)
    }
  })
}
// FIX: Updated visual indicator function to properly display different statuses with correct colors
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

// Log when the background script loads
console.log("Background script loaded")

const API_URL = "http://127.0.0.1:8000/v1/check-url";

// Listen to navigation events
chrome.webNavigation.onCommitted.addListener(async (details) => {
    // Only process main frame navigations (not iframes) and ignore extension/local URLs
    if (details.frameId === 0 && details.url.startsWith("http")) {
        console.log("Analyzing URL:", details.url);
        
        try {
            const response = await fetch(API_URL, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    url: details.url,
                    mode: "quick" // Use quick mode for fast response during browsing
                })
            });

            if (!response.ok) {
                console.error("API Error:", response.statusText);
                return;
            }

            const data = await response.json();
            console.log("Analysis result:", data);

            // Save result to storage so popup can read it
            chrome.storage.local.set({ [details.url]: data });

            // If dangerous, send message to content script to block UI
            if (data.verdict === "DANGEROUS" || data.risk_score >= 70) {
                chrome.tabs.sendMessage(details.tabId, {
                    action: "SHOW_WARNING",
                    data: data
                }).catch(err => console.log("Content script not ready yet", err));
            }

        } catch (error) {
            console.error("Failed to connect to PhishGuardAI backend:", error);
        }
    }
});

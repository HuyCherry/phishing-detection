document.addEventListener('DOMContentLoaded', async () => {
    // Get current active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab || !tab.url.startsWith('http')) {
        updateUI(null, "Không hỗ trợ trang này");
        return;
    }

    // Check if we have cached data for this URL
    chrome.storage.local.get([tab.url], (result) => {
        const data = result[tab.url];
        if (data) {
            updateUI(data);
        } else {
            // If no cache, trigger an analysis
            analyzeUrl(tab.url);
        }
    });

    document.getElementById('btn-report').addEventListener('click', () => {
        window.open('http://127.0.0.1:8501', '_blank');
    });

    // New Scan Page feature
    const btnScan = document.getElementById('btn-scan');
    if (btnScan) {
        btnScan.addEventListener('click', async () => {
            btnScan.innerText = "Đang quét...";
            btnScan.disabled = true;
            try {
                chrome.tabs.sendMessage(tab.id, { action: "scan_page_dom" }, (response) => {
                    btnScan.innerText = "🔍 Quét Email/Trang này";
                    btnScan.disabled = false;
                    if (chrome.runtime.lastError) {
                        // Content script not ready or not injected
                        updateUI(null, "Không thể quét trang này");
                    }
                });
            } catch (err) {
                btnScan.innerText = "🔍 Quét Email/Trang này";
                btnScan.disabled = false;
            }
        });
    }
});

async function analyzeUrl(url) {
    try {
        const response = await fetch("http://127.0.0.1:8000/v1/check-url", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url, mode: "quick" })
        });

        if (response.ok) {
            const data = await response.json();
            chrome.storage.local.set({ [url]: data });
            updateUI(data);
        } else {
            updateUI(null, "Lỗi kết nối máy chủ");
        }
    } catch (e) {
        updateUI(null, "Không thể kết nối PhishGuardAI");
    }
}

function updateUI(data, errorMsg = null) {
    const box = document.getElementById('status-box');
    const title = document.getElementById('verdict-title');
    const score = document.getElementById('risk-score');
    const flagsContainer = document.getElementById('flags-container');
    const flagsList = document.getElementById('flags-list');

    // Reset classes
    box.className = 'status-box';

    if (errorMsg) {
        title.innerText = errorMsg;
        score.innerText = "Vui lòng mở app chính để quét.";
        return;
    }

    if (!data) return;

    if (data.verdict === "DANGEROUS") {
        box.classList.add('dangerous');
        title.innerText = "NGUY HIỂM";
        score.innerHTML = `Điểm rủi ro: <strong>${data.risk_score}%</strong>`;
    } else if (data.verdict === "SUSPICIOUS") {
        box.classList.add('suspicious');
        title.innerText = "ĐÁNG NGỜ";
        score.innerHTML = `Điểm rủi ro: <strong>${data.risk_score}%</strong>`;
    } else {
        box.classList.add('safe');
        title.innerText = "AN TOÀN";
        score.innerHTML = `Điểm rủi ro: <strong>${data.risk_score}%</strong>`;
        
        if (data.is_official) {
            score.innerHTML += "<br>✅ Website chính thức";
        }
    }

    if (data.flags && data.flags.length > 0) {
        flagsContainer.style.display = 'block';
        flagsList.innerHTML = data.flags.map(f => `<li>${f}</li>`).join('');
    } else {
        flagsContainer.style.display = 'none';
    }
}

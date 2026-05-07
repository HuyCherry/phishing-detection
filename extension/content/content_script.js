chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "SHOW_WARNING") {
        showWarningBanner(request.data);
    } else if (request.action === "scan_page_dom") {
        scanPageDom();
        sendResponse({status: "started"});
    }
});

async function scanPageDom() {
    // 1. Send HTML to API
    const htmlContent = document.documentElement.outerHTML;
    try {
        chrome.runtime.sendMessage({
            action: "api_check_html",
            payload: { html_content: htmlContent, source_url: window.location.href }
        }, (response) => {
            if (response && response.success) {
                const data = response.data;
                if (data.html_risk_score >= 30) {
                    // Flash the screen red briefly to indicate risk found in HTML
                    const overlay = document.createElement("div");
                    overlay.style.position = "fixed";
                    overlay.style.top = "0"; overlay.style.left = "0"; overlay.style.width = "100%"; overlay.style.height = "100%";
                    overlay.style.backgroundColor = "rgba(255,0,0,0.2)";
                    overlay.style.zIndex = "9999999";
                    overlay.style.pointerEvents = "none";
                    document.body.appendChild(overlay);
                    setTimeout(() => overlay.remove(), 2000);
                }
            }
        });
    } catch(e) {
        console.error("HTML Check failed", e);
    }

    // 2. Scan links in the page
    const links = document.querySelectorAll('a[href]');
    let linkUrls = new Set();
    links.forEach(link => {
        if (link.href.startsWith('http') && !link.href.includes('google.com') && !link.href.includes(window.location.hostname)) {
            linkUrls.add(link.href);
        }
    });

    for (let url of linkUrls) {
        try {
            chrome.runtime.sendMessage({
                action: "api_check_url",
                payload: { url: url, mode: "quick" }
            }, (response) => {
                if (response && response.success) {
                    const data = response.data;
                    if (data.verdict === "DANGEROUS" || data.verdict === "SUSPICIOUS") {
                        links.forEach(link => {
                            if (link.href === url) {
                                link.style.backgroundColor = "rgba(255, 0, 0, 0.3)";
                                link.style.border = "2px dashed red";
                                link.style.color = "red";
                                link.title = `⚠️ PhishGuardAI: Link nguy hiểm! (${data.risk_score}%)`;
                                
                                // Add a warning icon next to it
                                const warning = document.createElement("span");
                                warning.innerText = " 🛑";
                                link.parentNode.insertBefore(warning, link.nextSibling);
                            }
                        });
                    }
                }
            });
        } catch(e) {}
    }
}

function showWarningBanner(data) {
    // If banner already exists, don't create another
    if (document.getElementById("phishguard-warning-banner")) return;

    const banner = document.createElement("div");
    banner.id = "phishguard-warning-banner";

    let flagsHtml = "";
    if (data.flags && data.flags.length > 0) {
        flagsHtml = `
            <div class="phishguard-flags">
                <strong>Dấu hiệu nhận biết:</strong>
                <ul>
                    ${data.flags.map(f => `<li>${f}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    banner.innerHTML = `
        <div class="phishguard-content">
            <h1>CẢNH BÁO TRANG WEB LỪA ĐẢO!</h1>
            <p>Hệ thống PhishGuardAI phát hiện trang web này có rủi ro rất cao (<strong>${data.risk_score}%</strong>) và có thể đang cố đánh cắp thông tin cá nhân của bạn.</p>
            ${flagsHtml}
            <div class="phishguard-buttons">
                <button class="phishguard-btn-back" id="pg-btn-back">Quay lại an toàn</button>
                <button class="phishguard-btn-ignore" id="pg-btn-ignore">Tôi hiểu rủi ro, tiếp tục</button>
            </div>
        </div>
    `;

    document.body.appendChild(banner);
    document.body.style.overflow = "hidden"; // Prevent scrolling

    // Event listeners for buttons
    document.getElementById("pg-btn-back").addEventListener("click", () => {
        window.history.back();
        // Fallback if history is empty
        setTimeout(() => { window.location.href = "https://www.google.com"; }, 500);
    });

    document.getElementById("pg-btn-ignore").addEventListener("click", () => {
        banner.remove();
        document.body.style.overflow = ""; // Restore scrolling
    });
}

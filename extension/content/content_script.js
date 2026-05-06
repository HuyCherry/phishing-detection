chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "SHOW_WARNING") {
        showWarningBanner(request.data);
    }
});

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

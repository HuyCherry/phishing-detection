import streamlit as st
import pickle
import pandas as pd
import re
import os

st.set_page_config(page_title="Phishing Detection", layout="centered")
st.title("🛡️ Hệ thống Phát hiện Phishing")
st.write("Dán URL cần kiểm tra bên dưới:")

# Load model
@st.cache_resource
def load_model():
    model_path = r'E:\Phishing-Detection\model\phishing_model.pkl'
    with open(model_path, 'rb') as f:
        data = pickle.load(f)
    return data['model'], data['feature_names']

try:
    model, feature_names = load_model()
except Exception as e:
    st.error(f"❌ Lỗi load model: {str(e)}")
    st.info("💡 Hãy train lại model trước!")
    st.stop()

# 🔥 HÀM TỰ ĐỘNG TRÍCH XUẤT ĐẶC TRƯNG TỪ URL
def extract_features_from_url(url, feature_names):
    """
    Tự động trích xuất tất cả features từ URL
    Trả về dict với keys trùng với feature_names
    """
    features = {}
    
    # Khởi tạo tất cả features = 0
    for name in feature_names:
        features[name] = 0
    
    try:
        # 1. Các features cơ bản
        features['UrlLength'] = len(url)
        features['NumDots'] = url.count('.')
        features['NumDash'] = url.count('-')
        features['AtSymbol'] = 1 if '@' in url else 0
        features['NumUnderscore'] = url.count('_')
        features['NumPercent'] = url.count('%')
        
        # 2. Kiểm tra IP
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        features['IpAddress'] = 1 if re.search(ip_pattern, url) else 0
        
        # 3. HTTPS
        features['HttpsInHostname'] = 1 if 'https' in url.lower() else 0
        
        # 4. Phân tích domain/path
        if '//' in url:
            parts = url.split('//')[1].split('/')
            domain = parts[0] if parts else ""
            path = '/'.join(parts[1:]) if len(parts) > 1 else ""
        else:
            domain = ""
            path = ""
        
        features['SubdomainLevel'] = domain.count('.') 
        features['PathLength'] = len(path)
        features['DoubleSlashInPath'] = 1 if '//' in path else 0
        
        # 5. Query parameters
        if '?' in url:
            query = url.split('?')[1]
            features['NumQueryComponents'] = query.count('&') + 1
            features['QueryLength'] = len(query)
        else:
            features['NumQueryComponents'] = 0
            features['QueryLength'] = 0
        
        # 6. Từ khóa nhạy cảm
        sensitive_words = ['login', 'bank', 'secure', 'verify', 'update', 'account', 'signin', 'password']
        features['NumSensitiveWords'] = sum(1 for word in sensitive_words if word in url.lower())
        
        # 7. Các ký tự đặc biệt
        features['NumAmpersand'] = url.count('&')
        features['NumHash'] = url.count('#')
        features['NumSlash'] = url.count('/')
        
        # 8. Random string (đơn giản: kiểm tra tỷ lệ ký tự số/chữ)
        digits = sum(c.isdigit() for c in url)
        features['NumNumericChars'] = digits
        
        # 9. Domain trong path
        features['DomainInPaths'] = 1 if '.' in path else 0
        
        # 10. Các features khác (set default = 0 nếu không tính được)
        features['NumDashInHostname'] = domain.count('-')
        features['HostnameLength'] = len(domain)
        features['PctExtHyperlinks'] = 0
        features['PctExtResourceUrls'] = 0
        features['PctExtNullSelfRedirectHyperlinksRT'] = 0
        features['ExtMetaScriptLinkRT'] = 0
        features['AbnormalExtFormActionR'] = 0
        features['ExtFormAction'] = 0
        features['AbnormalFormAction'] = 0
        features['RelativeFormAction'] = 0
        features['InsecureForms'] = 0
        features['ExtFavicon'] = 0
        features['FrequentDomainNameMismatch'] = 0
        features['FakeLinkInStatusBar'] = 0
        features['RightClickDisabled'] = 0
        features['PopUpWindow'] = 0
        features['SubmitInfoToEmail'] = 0
        features['IframeOrFrame'] = 0
        features['MissingTitle'] = 0
        features['ImagesOnlyInForm'] = 0
        features['SubdomainLevelRT'] = 0
        features['UrlLengthHRT'] = 0
        features['PctExtResourceUrlsRT'] = 0
        features['AbnormalExtFormActionRT'] = 0
        features['EmbeddedBrandName'] = 0
        features['DomainInSubdomains'] = 0
        features['NoHttps'] = 0 if features['HttpsInHostname'] else 1
        features['RandomString'] = 0
        features['TildeSymbol'] = url.count('~')
        features['NumSensitiveWords'] = features.get('NumSensitiveWords', 0)
        
    except Exception as e:
        st.warning(f"⚠️ Lỗi trích xuất features: {str(e)}")
    
    return features

# Giao diện
url_input = st.text_input("URL cần kiểm tra", placeholder="https://example.com/login")

if st.button("🔍 Kiểm tra", type="primary"):
    if not url_input.strip():
        st.warning("⚠️ Vui lòng nhập URL!")
    else:
        with st.spinner("⏳ Đang phân tích URL..."):
            try:
                # Tự động trích xuất features
                features_dict = extract_features_from_url(url_input, feature_names)
                
                # Tạo DataFrame với đúng thứ tự columns
                X_input = pd.DataFrame([features_dict])[feature_names]
                
                # Predict
                prediction = model.predict(X_input)[0]
                proba = model.predict_proba(X_input)[0]
                
                st.divider()
                
                if prediction == 1:
                    st.error("🚨 CẢNH BÁO: URL LỪA ĐẢO!")
                    st.info(f"📉 Độ tin cậy: {proba[1]*100:.2f}% nguy hiểm")
                    st.markdown("💡 **Khuyến nghị**: Không nhập thông tin cá nhân, mật khẩu hoặc thẻ ngân hàng!")
                else:
                    st.success("✅ URL AN TOÀN")
                    st.info(f"📈 Độ tin cậy: {proba[0]*100:.2f}% an toàn")
                
                # Hiển thị các features đã trích xuất (collapse)
                with st.expander("📊 Xem chi tiết các đặc trưng"):
                    st.json(features_dict)
                    
            except Exception as e:
                st.error(f"❌ Lỗi: {str(e)}")
                st.info("💡 Kiểm tra lại: model đã train chưa? URL có hợp lệ không?")

# Footer
st.divider()
st.caption("🔒 Hệ thống sử dụng Machine Learning (Random Forest) để phát hiện URL phishing")
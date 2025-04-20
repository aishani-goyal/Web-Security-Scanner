# 🌐 CyberSafe - Website Security Scanner

## 📌 Overview  
The **Website Security Scanner** is a tool designed to analyze website URLs for security vulnerabilities, trust scores, SSL certificate validity, and backlink analysis. It helps users assess the reliability of a website by displaying key security metrics in an intuitive visual format.

---

## 🚀 Features  

- 🔍 **Trust Score Analysis**: Evaluate a website's credibility based on various security parameters  
- 🛡 **Vulnerability Detection**: Identify potential security risks using the OWASP ZAP API  
- 🔗 **Backlink Analysis**: Check inbound links to determine a website’s authenticity  
- 🔒 **SSL Certificate Validation**: Verify if a website has a valid SSL certificate  
- 📊 **Graphical Representation**: Display security metrics using interactive charts  

---

## 🛠 Tech Stack  

- **Frontend**: HTML, CSS, JavaScript, Bootstrap  
- **Backend**: Python  
- **APIs Used**:
  - [VirusTotal API](https://www.virustotal.com/)
  - [OWASP ZAP API](https://www.zaproxy.org/)

---

## 🔧 Installation & Setup  

1. **Clone the repository**  
   ```bash
   git clone https://github.com/yourusername/website-scanner.git
   cd website-scanner
   ```

2. **Install dependencies**  
   ```bash
   pip install -r backend/requirements.txt
   ```

3. **Set up OWASP ZAP**  
   - Install OWASP ZAP on your system  
   - Update the API key in `backend/back.py`

4. **Run the backend**  
   ```bash
   python backend/back.py
   ```

5. **Open frontend**  
   - Launch `frontend/front.html` in a browser

---

## 🔗 Live Demo

▶️ **Watch the Demo Video Below**
---
https://drive.google.com/file/d/1AT-a48vNWlijMheJn-SUlUbIv3nxmxrx/view?usp=sharing

<video width="100%" controls>
  <source src="demo.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

---

## ✅ How It Works

- Enter a website URL in the input field  
- Click the **"Scan"** button to analyze the site  
- View trust score, vulnerabilities, and SSL status in the visual dashboard  
- Click on charts for detailed analysis  


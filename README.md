# XSS Scanner 🔍

A powerful and automated **Cross-Site Scripting (XSS) scanner** that detects Reflected, DOM-based, and Blind XSS vulnerabilities in web applications.

## 🚀 Features

- ✅ **Reflected XSS Detection** – Tests for reflected input in responses.
- ✅ **DOM-based XSS Detection** – Uses Selenium to detect vulnerabilities in JavaScript-heavy applications.
- ✅ **Blind XSS Testing** – Supports webhook-based detection.
- ✅ **Custom Payloads & Encoding** – Supports URL encoding, Base64, and template injection.
- ✅ **Multithreading for Faster Scanning** – Efficient scanning with threading.
- ✅ **Output Results to JSON or CSV** – Export vulnerability findings for later analysis.
- ✅ **Supports GET and POST Requests** – Flexible HTTP method options.

---

## 🛠️ Installation

1. **Clone the repository**  
   ```bash
   git clone https://github.com/KishanKhetia/xss_scanner.git
   cd xss_scanner
   ```

2. **Install dependencies**  
   ```bash
   pip install -r requirements.txt
   ```

3. **(Optional) Install Google Chrome & Chromedriver** (for DOM XSS detection)  
   - **Linux**:  
     ```bash
     sudo apt install -y google-chrome-stable
     ```
   - **Windows**: Download [ChromeDriver](https://chromedriver.chromium.org/downloads) and place it in your PATH.

---

## 🎯 Usage

### Basic Scan
Scan a target URL for XSS vulnerabilities with default settings.

```bash
python xss_scanner.py -u "http://example.com"
Scanning with Specific Parameters
Specify which parameters to test for XSS.

bash
Copy
Edit
python xss_scanner.py -u "http://example.com/search" -p q
Choosing HTTP Method
Specify GET or POST for sending requests.

bash
Copy
Edit
python xss_scanner.py -u "http://example.com/login" -p username password -m POST
Sending Authentication Cookies
If the target requires authentication, pass session cookies.

bash
Copy
Edit
python xss_scanner.py -u "http://example.com/dashboard" -c "sessionid=abcd1234"
Defining Data Format (JSON, XML, Query)
Send payloads in different formats for POST requests.

bash
Copy
Edit
python xss_scanner.py -u "http://example.com/api" -p data -m POST -f json
Blind XSS Testing via Webhook
Send payloads to an external webhook for detection.

bash
Copy
Edit
python xss_scanner.py -u "http://example.com/comment" -w "https://your-webhook-url.com"
Saving Results
Export scan results in JSON or CSV format.

bash
Copy
Edit
python xss_scanner.py -u "http://example.com" -o results.json
Enabling Verbose Mode
Get detailed logs during scanning.

bash
Copy
Edit
python xss_scanner.py -u "http://example.com" -v
---

## 🏗️ Requirements

- Python 3.x
- `requests`
- `selenium`
- `argparse`
- `chromedriver` (for DOM XSS scanning)

---

## ⚠️ Disclaimer

This tool is **for educational and security testing purposes only**. **Do not use it on websites you do not own or have explicit permission to test.** The developer is not responsible for any misuse of this tool.

---


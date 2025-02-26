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

### Basic XSS Scan
```bash
python xss_scanner.py -u "http://example.com" -p "search"
```

### Scanning with POST requests
```bash
python xss_scanner.py -u "http://example.com/login" -p "username" "password" -m POST
```

### Enable verbose mode
```bash
python xss_scanner.py -u "http://example.com" -p "query" -v
```

### Export results to JSON or CSV
```bash
python xss_scanner.py -u "http://example.com" -p "query" -o results.json
python xss_scanner.py -u "http://example.com" -p "query" -o results.csv
```

### Blind XSS Testing (Using Webhook)
```bash
python xss_scanner.py -u "http://example.com" -p "query" -w "https://webhook.site/your-webhook-url"
```

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


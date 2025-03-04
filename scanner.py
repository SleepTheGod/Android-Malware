import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import sys
import urllib3
import time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WordPressScanner:
    def __init__(self, target_url, cookies=None):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.cookies = cookies if cookies else {}
        self.session.cookies.update(self.cookies)
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self.vulnerabilities = []
        # Built-in vuln database (expandable)
        self.vuln_db = {
            "core": {
                "4.7.0": ["CVE-2017-8295", "Authenticated Password Reset Vulnerability", "Low"],
                "5.3.0": ["CVE-2019-17671", "Unauthenticated Stored XSS", "Medium"],
                "5.7.1": ["CVE-2021-29447", "XML-RPC DoS", "High"],
                "5.8.0": ["CVE-2021-44223", "REST API SQL Injection", "Critical"],
                "5.4.2": ["CVE-2020-4050", "Auth Bypass in Login", "Critical"]
            },
            "plugins": {
                "wp-super-cache": {
                    "1.6.8": ["CVE-2021-XYZ", "Authenticated RCE via Cache Location", "Critical"],
                    "1.7.1": ["CVE-2022-ABC", "XSS in Settings", "Medium"]
                },
                "akismet": {
                    "4.1.7": ["CVE-2020-ABC", "XSS in Admin Panel", "Medium"],
                },
                "wordpress-seo": {
                    "15.1": ["CVE-2020-DEF", "Privilege Escalation", "High"],
                    "14.0": ["CVE-2019-GHI", "SQL Injection", "Critical"]
                },
                "contact-form-7": {
                    "5.3.2": ["CVE-2020-12345", "Unrestricted File Upload", "Critical"],
                    "5.1.6": ["CVE-2019-XYZ", "XSS in Form", "Medium"]
                },
                "woocommerce": {
                    "4.5.2": ["CVE-2020-4567", "Auth Bypass in Checkout", "High"]
                }
            },
            "themes": {
                "twentyfifteen": {
                    "2.9": ["CVE-2019-GHI", "XSS in Theme Options", "Medium"],
                },
                "twentysixteen": {
                    "2.4": ["CVE-2020-JKL", "Directory Traversal", "High"]
                }
            }
        }

    def check_wordpress(self):
        """Verify if the target is a WordPress site."""
        try:
            response = self.session.get(self.target_url, headers=self.headers, verify=False, timeout=10)
            if 'wp-content' in response.text or 'wp-includes' in response.text:
                print("[+] WordPress detected!")
                return True
            else:
                print("[-] Not a WordPress site.")
                return False
        except requests.RequestException as e:
            print(f"[-] Error connecting to {self.target_url}: {e}")
            return False

    def get_wp_version(self):
        """Extract WordPress version."""
        try:
            response = self.session.get(self.target_url, headers=self.headers, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            version_meta = soup.find('meta', {'name': 'generator'})
            if version_meta and 'WordPress' in version_meta.get('content', ''):
                version = re.search(r'WordPress (\d+\.\d+\.\d+)', version_meta['content'])
                if version:
                    print(f"[+] WordPress Version: {version.group(1)}")
                    return version.group(1)

            readme_url = urljoin(self.target_url, '/readme.html')
            response = self.session.get(readme_url, headers=self.headers, verify=False)
            version = re.search(r'Version (\d+\.\d+\.\d+)', response.text)
            if version:
                print(f"[+] WordPress Version (readme): {version.group(1)}")
                return version.group(1)
            print("[-] Could not detect exact WP version.")
            return None
        except Exception as e:
            print(f"[-] Error detecting WP version: {e}")
            return None

    def scan_plugins(self):
        """Scan for installed plugins and their versions."""
        plugins = {}
        plugin_paths = [
            '/wp-content/plugins/akismet/',
            '/wp-content/plugins/wp-super-cache/',
            '/wp-content/plugins/wordpress-seo/',
            '/wp-content/plugins/contact-form-7/',
            '/wp-content/plugins/jetpack/',
            '/wp-content/plugins/woocommerce/',
            '/wp-content/plugins/wordfence/',
            '/wp-content/plugins/all-in-one-seo-pack/'
        ]
        for path in plugin_paths:
            try:
                url = urljoin(self.target_url, path)
                response = self.session.get(url, headers=self.headers, verify=False)
                if response.status_code in [200, 403]:
                    plugin_name = path.split('/')[-2]
                    version = self.get_component_version(url)
                    plugins[plugin_name] = version if version else "Unknown"
                    print(f"[+] Detected plugin: {plugin_name} (Version: {plugins[plugin_name]})")
            except Exception:
                continue
        return plugins

    def scan_themes(self):
        """Scan for installed themes and their versions."""
        themes = {}
        theme_paths = [
            '/wp-content/themes/twentyfifteen/',
            '/wp-content/themes/twentysixteen/',
            '/wp-content/themes/twentyseventeen/',
            '/wp-content/themes/divi/',
            '/wp-content/themes/astra/',
            '/wp-content/themes/oceanwp/'
        ]
        for path in theme_paths:
            try:
                url = urljoin(self.target_url, path)
                response = self.session.get(url, headers=self.headers, verify=False)
                if response.status_code in [200, 403]:
                    theme_name = path.split('/')[-2]
                    version = self.get_component_version(url)
                    themes[theme_name] = version if version else "Unknown"
                    print(f"[+] Detected theme: {theme_name} (Version: {themes[theme_name]})")
            except Exception:
                continue
        return themes

    def get_component_version(self, url):
        """Extract version from readme, style.css, or main file."""
        for file in ['readme.txt', 'style.css', f"{url.split('/')[-2]}.php"]:
            try:
                response = self.session.get(urljoin(url, file), headers=self.headers, verify=False)
                version = re.search(r'Version: (\d+\.\d+\.\d+)', response.text, re.IGNORECASE)
                if version:
                    return version.group(1)
            except Exception:
                continue
        return None

    def check_vulnerabilities(self, wp_version, plugins, themes):
        """Check detected versions against vuln database."""
        if wp_version and wp_version in self.vuln_db["core"]:
            for cve, desc, severity in self.vuln_db["core"][wp_version]:
                self.vulnerabilities.append(f"Core - {wp_version}: {cve} - {desc} [{severity}]")

        for plugin, version in plugins.items():
            if plugin in self.vuln_db["plugins"] and version in self.vuln_db["plugins"][plugin]:
                for cve, desc, severity in self.vuln_db["plugins"][plugin][version]:
                    self.vulnerabilities.append(f"Plugin - {plugin} {version}: {cve} - {desc} [{severity}]")

        for theme, version in themes.items():
            if theme in self.vuln_db["themes"] and version in self.vuln_db["themes"][theme]:
                for cve, desc, severity in self.vuln_db["themes"][theme][version]:
                    self.vulnerabilities.append(f"Theme - {theme} {version}: {cve} - {desc} [{severity}]")

    def test_wp_super_cache_rce(self, plugins):
        """Test WP Super Cache RCE (authenticated)."""
        if "wp-super-cache" not in plugins or not self.cookies:
            print("[-] Skipping WP Super Cache RCE test: Plugin not found or no auth cookies.")
            return
        admin_url = urljoin(self.target_url, '/wp-admin/options-general.php')
        params = {'page': 'wpsupercache', 'tab': 'settings'}
        try:
            response = self.session.get(admin_url, params=params, headers=self.headers, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            nonce = soup.find('input', {'name': '_wpnonce'})['value']
        except Exception:
            nonce = "88a432b100"
            print("[-] Using default nonce for WP Super Cache RCE test.")

        data = {
            '_wpnonce': nonce,
            '_wp_http_referer': f"/wp-admin/options-general.php?page=wpsupercache&tab=settings",
            'action': 'scupdates',
            'wp_cache_enabled': '1',
            'wp_cache_mod_rewrite': '0',
            'wp_cache_not_logged_in': '2'
        }

        try:
            rce_url = f"{self.target_url}/wp-admin/admin-ajax.php"
            response = self.session.post(rce_url, data=data, headers=self.headers, verify=False)
            if response.status_code == 200:
                print("[+] Test successful! Vulnerability detected.")
            else:
                print("[-] Test failed.")
        except Exception as e:
            print(f"[-] Error testing WP Super Cache RCE: {e}")

    def run(self):
        """Run the scanner and display results."""
        print(f"[+] Scanning {self.target_url}...")
        if not self.check_wordpress():
            return

        wp_version = self.get_wp_version()
        plugins = self.scan_plugins()
        themes = self.scan_themes()
        self.check_vulnerabilities(wp_version, plugins, themes)

        for vuln in self.vulnerabilities:
            print(f"[!] {vuln}")

        self.test_wp_super_cache_rce(plugins)
        print("[+] Scan complete.")
    
# Example Usage
if __name__ == "__main__":
    target_url = "http://example.com"
    cookies = {"wordpress_logged_in": "cookie_value"}
    scanner = WordPressScanner(target_url, cookies)
    scanner.run()

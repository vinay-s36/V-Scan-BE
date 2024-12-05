from flask import send_from_directory
import requests
import re
import os
from bs4 import BeautifulSoup
import urllib.parse
import ssl
import socket
import concurrent.futures
import warnings
from typing import List, Dict
from flask import Flask, request, abort
from flask_cors import CORS
from urllib.parse import urlparse

warnings.filterwarnings("ignore", category=UserWarning)
app = Flask(__name__)
CORS(app)


class WebVulnerabilityScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.base_url = urllib.parse.urlparse(target_url).netloc
        self.scanned_pages = set()
        self.vulnerabilities = []

    def crawl_website(self, max_pages: int = 50) -> List[str]:
        """Recursively crawl website and collect unique pages"""
        urls_to_scan = [self.target_url]
        crawled_urls = []

        while urls_to_scan and len(crawled_urls) < max_pages:
            current_url = urls_to_scan.pop(0)

            if current_url in self.scanned_pages:
                continue

            try:
                response = requests.get(current_url, timeout=5)
                if response.status_code == 200:
                    crawled_urls.append(current_url)
                    self.scanned_pages.add(current_url)

                    soup = BeautifulSoup(response.text, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        absolute_link = urllib.parse.urljoin(
                            current_url, link['href'])

                        # Only crawl links from same domain
                        if self.base_url in absolute_link and absolute_link not in self.scanned_pages:
                            urls_to_scan.append(absolute_link)

            except Exception:
                continue

        return crawled_urls

    def sql_injection_scan(self, urls: List[str]) -> List[Dict]:
        """Detect potential SQL Injection vulnerabilities"""
        sql_vulnerabilities = []
        sql_test_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "1' ORDER BY 1--+"
        ]

        for url in urls:
            for payload in sql_test_payloads:
                try:
                    test_url = f"{url}?id={payload}"
                    response = requests.get(test_url, timeout=5)

                    # Basic heuristic for detecting potential SQL injection
                    if any(keyword in response.text.lower() for keyword in ['error', 'mysql', 'syntax']):
                        sql_vulnerabilities.append({
                            'type': 'SQL Injection',
                            'url': url,
                            'payload': payload,
                            'risk': 'High'
                        })
                except Exception:
                    pass

        return sql_vulnerabilities

    def xss_scan(self, urls: List[str]) -> List[Dict]:
        """Detect potential Cross-Site Scripting vulnerabilities"""
        xss_vulnerabilities = []
        xss_payloads = [
            '<script>alert("XSS")</script>',
            'javascript:alert("XSS")',
            '<img src=x onerror=alert("XSS")>'
        ]

        for url in urls:
            for payload in xss_payloads:
                try:
                    test_url = f"{url}?input={urllib.parse.quote(payload)}"
                    response = requests.get(test_url, timeout=5)

                    if payload in response.text:
                        xss_vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'url': url,
                            'payload': payload,
                            'risk': 'High'
                        })
                except Exception:
                    pass

        return xss_vulnerabilities

    def security_headers_check(self) -> List[Dict]:
        """Check security headers"""
        headers_vulnerabilities = []
        try:
            response = requests.head(self.target_url)
            headers = response.headers

            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS header',
                'X-Frame-Options': 'Missing clickjacking protection',
                'X-XSS-Protection': 'Missing XSS protection header',
                'Content-Security-Policy': 'Missing CSP header'
            }

            for header, description in security_headers.items():
                if header.lower() not in map(str.lower, headers.keys()):
                    headers_vulnerabilities.append({
                        'type': 'Security Header Missing',
                        'header': header,
                        'description': description,
                        'risk': 'Medium'
                    })

        except Exception:
            pass

        return headers_vulnerabilities

    def ssl_check(self) -> List[Dict]:
        """Check SSL/TLS configuration"""
        ssl_vulnerabilities = []
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.base_url, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.base_url) as secure_sock:
                    cert = secure_sock.getpeercert()

                    # Check certificate expiration
                    import datetime
                    expiry = datetime.datetime.strptime(
                        cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if expiry < datetime.datetime.now():
                        ssl_vulnerabilities.append({
                            'type': 'SSL Certificate Expired',
                            'risk': 'High'
                        })

        except ssl.SSLError as e:
            ssl_vulnerabilities.append({
                'type': 'SSL Configuration Issue',
                'details': str(e),
                'risk': 'Critical'
            })
        except Exception:
            ssl_vulnerabilities.append({
                'type': 'SSL Configuration Issue',
                'risk': 'Critical'
            })

        return ssl_vulnerabilities

    def scan_website(self) -> List[Dict]:
        """Main scanning method"""
        print(f"Scanning {self.target_url}...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            pages = executor.submit(self.crawl_website).result()

            vulnerability_checks = [
                executor.submit(self.sql_injection_scan, pages),
                executor.submit(self.xss_scan, pages),
                executor.submit(self.security_headers_check),
                executor.submit(self.ssl_check)
            ]

            for future in concurrent.futures.as_completed(vulnerability_checks):
                self.vulnerabilities.extend(future.result())

        return len(self.vulnerabilities)

    def generate_report(self):
        """Generate vulnerability report"""

        if not os.path.exists('scan_reports'):
            os.makedirs('scan_reports')

        filename = os.path.join('scan_reports', re.sub(r'[^a-zA-Z0-9]', '_', self.target_url.replace(
            'https://', '').replace('http://', '')) + '_vulnerability_report.txt')

        with open(filename, 'w', encoding='utf-8') as report_file:
            report_file.write("Web Vulnerability Scan Report\n")
            report_file.write(f"Target: {self.target_url}\n\n")

            if not self.vulnerabilities:
                report_file.write("No significant vulnerabilities detected!\n")
                print(f"Report saved to {filename}")
                return

            for vuln in self.vulnerabilities:
                report_file.write(
                    f"[{vuln.get('risk', 'Unknown')}] {vuln.get('type', 'Unknown Vulnerability')}\n")
                if 'url' in vuln:
                    report_file.write(f"   URL: {vuln['url']}\n")
                if 'payload' in vuln:
                    report_file.write(f"   Payload: {vuln['payload']}\n")
                report_file.write('\n')

        return filename


def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return all([parsed.scheme, parsed.netloc])
    except ValueError:
        return False


@app.route('/reports/<path:filename>', methods=['GET'])
def download_report(filename):
    print(filename)
    try:
        safe_filename = os.path.basename(filename)
        file_path = os.path.join('scan_reports', safe_filename)

        if not file_path.startswith(os.path.join('scan_reports', '')):
            return abort(403, description="Forbidden access to file outside scan_reports")

        if not os.path.exists(file_path):
            return abort(404, description="File not found")

        return send_from_directory(
            directory="./scan_reports",
            path=safe_filename,
            as_attachment=True
        )
    except Exception as e:
        return str(e), 404


@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        if not data or 'target_url' not in data:
            return "Missing 'target_url' in request body", 400

        target_url = data['target_url']

        if not is_valid_url(target_url):
            return "Invalid URL format", 400

        scanner = WebVulnerabilityScanner(target_url)
        total_vulnerabilities = scanner.scan_website()
        filename = scanner.generate_report()

        return {"status": "success", "report": filename, "total_vulnerabilities": total_vulnerabilities}, 200
    except Exception as e:
        return {"error": str(e)}, 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)

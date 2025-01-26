from bs4 import BeautifulSoup
import urllib.parse
import ssl
import socket
import concurrent.futures
import requests
import re
from typing import List, Dict
import os
from datetime import datetime


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

    def check_ssl_certificate(self) -> List[Dict]:
        """Checks the validity of an SSL certificate for a given hostname."""
        ssl_vulnerabilities = []
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.base_url, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.base_url) as ssock:
                    cert = ssock.getpeercert()
                    # Extract certificate details
                    issue_date = datetime.strptime(
                        cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    expiry_date = datetime.strptime(
                        cert['notAfter'], '%b %d %H:%M:%S %Y %Z')

                    # Check if certificate is valid
                    if issue_date <= datetime.now() <= expiry_date:
                        pass
                    else:
                        ssl_vulnerabilities.append({
                            'type': 'SSL Certificate Expired',
                            'risk': 'High'
                        })
        except Exception as e:
            ssl_vulnerabilities.append({
                'type': 'SSL Configuration Issue',
                'risk': 'Critical'
            })
        return ssl_vulnerabilities

    def scan_website(self) -> List[Dict]:
        """Main scanning method"""

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            pages = executor.submit(self.crawl_website).result()

            vulnerability_checks = [
                executor.submit(self.sql_injection_scan, pages),
                executor.submit(self.xss_scan, pages),
                executor.submit(self.security_headers_check),
                executor.submit(self.check_ssl_certificate)
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

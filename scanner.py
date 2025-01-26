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
import whois
import nmap
import dns.resolver


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

    # Utility function for decoding data safely
    def safe_decode(self, value):
        if isinstance(value, bytes):
            return value.decode('utf-8', errors='ignore')
        elif isinstance(value, list):
            return [self.safe_decode(item) for item in value]
        elif isinstance(value, dict):
            return {self.safe_decode(k): self.safe_decode(v) for k, v in value.items()}
        return value

    # WHOIS information
    def get_whois_info(self):
        try:
            w = whois.whois(self.base_url)
            return {
                "domain_name": self.safe_decode(w.domain_name),
                "registrar": self.safe_decode(w.registrar),
                "creation_date": self.safe_decode(str(w.creation_date)),
                "expiration_date": self.safe_decode(str(w.expiration_date)),
                "name_servers": self.safe_decode(w.name_servers),
                "status": self.safe_decode(w.status),
            }
        except Exception as e:
            return {"error": str(e)}

    # DKIM check
    def check_dkim(self):
        try:
            selector = "mail"
            dkim_record = f"{selector}._domainkey.{self.base_url}"
            answers = dns.resolver.resolve(dkim_record, "TXT")
            for rdata in answers:
                if rdata.strings:
                    return {"dkim": "valid"}
            return {"dkim": "missing"}
        except dns.resolver.NoAnswer:
            return {"dkim": "missing"}
        except Exception as e:
            return {"dkim": "missing", "error": str(e)}

    # DMARC check
    def check_dmarc(self):
        try:
            dmarc_record = f"_dmarc.{self.base_url}"
            answers = dns.resolver.resolve(dmarc_record, "TXT")
            for rdata in answers:
                if rdata.strings:
                    return {"dmarc": "valid"}
            return {"dmarc": "missing"}
        except dns.resolver.NoAnswer:
            return {"dmarc": "missing"}
        except Exception as e:
            return {"dmarc": "missing", "error": str(e)}

    # SPF check
    def check_spf(self):
        try:
            answers = dns.resolver.resolve(self.base_url, "TXT")
            for rdata in answers:
                if any(b"v=spf1" in txt for txt in rdata.strings):
                    return {"spf": "valid"}
            return {"spf": "missing"}
        except dns.resolver.NoAnswer:
            return {"spf": "missing"}
        except Exception as e:
            return {"spf": "missing", "error": str(e)}

    # Check for exposed files
    def check_exposed_files(self):
        exposed_files = [".git/", ".env"]
        exposed_results = {}
        for file in exposed_files:
            url = f"http://{self.base_url}/{file}"
            try:
                response = requests.head(url, timeout=5)
                exposed_results[file] = "Accessible" if response.status_code == 200 else "Not Accessible"
            except Exception as e:
                exposed_results[file] = f"Error: {str(e)}"
        return exposed_results

    # DNS records analysis
    def scan_dns(self):
        try:
            answers = dns.resolver.resolve(self.base_url, "A")
            return [{"type": "A", "value": rdata.to_text()} for rdata in answers]
        except Exception as e:
            return {"error": str(e)}

    # Port scanning
    def scan_ports(self):
        try:
            nm = nmap.PortScanner()
            nm.scan(self.base_url, arguments="-T4 -Pn")
            open_ports = []
            for host in nm.all_hosts():
                for port in nm[host]["tcp"]:
                    open_ports.append(
                        {"port": port, "status": nm[host]["tcp"][port]["state"]})
            return open_ports
        except Exception as e:
            return {"error": str(e)}

    # OS detection
    def detect_os(self):
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=self.base_url, arguments="-O -sV -Pn")
            os_results = []
            if self.base_url in nm.all_hosts():
                for osmatch in nm[self.base_url].get("osmatch", []):
                    os_results.append({
                        "name": osmatch.get("name", "Unknown"),
                        "accuracy": osmatch.get("accuracy", 0),
                        "type": osmatch.get("type", "Unknown"),
                    })
            return os_results if os_results else {"os_detection": "No OS information detected"}
        except Exception as e:
            return {"error": str(e)}

    # WAF detection
    def detect_waf(self):
        try:
            url = f"http://{self.base_url}"
            response = requests.get(url, timeout=5)
            headers = response.headers
            waf_indicators = ["cloudflare", "sucuri", "imperva", "akamai"]
            detected_wafs = [indicator for indicator in waf_indicators if any(
                indicator in str(header).lower() for header in headers)]
            return {"waf_detected": bool(detected_wafs), "waf_vendors": detected_wafs}
        except Exception as e:
            return {"error": str(e)}

    def scan_website(self) -> List[Dict]:
        """Main scanning method"""

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            # Crawl pages
            pages = executor.submit(self.crawl_website).result()

            # Run different checks
            vulnerability_checks = [
                # executor.submit(self.sql_injection_scan, pages),
                # executor.submit(self.xss_scan, pages),
                # executor.submit(self.security_headers_check),
                # executor.submit(self.check_ssl_certificate),
                executor.submit(self.get_whois_info),
                executor.submit(self.check_dkim),
                executor.submit(self.check_dmarc),
                executor.submit(self.check_spf),
                executor.submit(self.detect_os),
                executor.submit(self.scan_ports),
                executor.submit(self.detect_waf),
                executor.submit(self.check_exposed_files),
                executor.submit(self.scan_dns)
            ]

            for future in concurrent.futures.as_completed(vulnerability_checks):
                self.vulnerabilities.extend(future.result())

        return len(self.vulnerabilities)

    def generate_report(self):
        """Generate vulnerability report"""

        if not os.path.exists('scan_reports'):
            os.makedirs('scan_reports')

        # Create a sanitized filename
        filename = os.path.join(
            'scan_reports',
            re.sub(r'[^a-zA-Z0-9]', '_',
                   self.target_url.replace('https://', '').replace('http://', ''))
            + '_vulnerability_report.txt'
        )

        with open(filename, 'w', encoding='utf-8') as report_file:
            report_file.write("Web Vulnerability Scan Report\n")
            report_file.write(f"Target: {self.target_url}\n\n")

            if not self.vulnerabilities:
                report_file.write("No significant vulnerabilities detected!\n")
                return filename

            for vuln in self.vulnerabilities:
                try:
                    # Write vulnerability details
                    report_file.write(
                        f"[{vuln.get('risk', 'Unknown')}] {vuln.get('type', 'Unknown Vulnerability')}\n")
                    if 'url' in vuln:
                        report_file.write(f"   URL: {vuln['url']}\n")
                    if 'payload' in vuln:
                        report_file.write(f"   Payload: {vuln['payload']}\n")
                    report_file.write('\n')
                except Exception as e:
                    # Log the error to the report and continue
                    report_file.write(
                        f"Error processing vulnerability: {vuln}\n")
                    report_file.write(f"   Exception: {str(e)}\n\n")

        return filename

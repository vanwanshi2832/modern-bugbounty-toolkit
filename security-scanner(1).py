#!/usr/bin/env python3

import argparse
import concurrent.futures
import requests
import dns.resolver
import socket
import subprocess
import sys
import json
from urllib.parse import urlparse
from datetime import datetime

class SecurityScanner:
    def __init__(self, target, output_file=None):
        self.target = target
        self.output_file = output_file
        self.results = {
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": target,
            "subdomains": [],
            "open_ports": [],
            "web_vulnerabilities": [],
            "dns_info": {},
            "headers_analysis": {}
        }
        # Disable SSL warnings
        requests.packages.urllib3.disable_warnings()

    def scan_subdomains(self):
        """Scan for subdomains using common techniques"""
        print("[+] Starting subdomain scan...")
        try:
            # Basic DNS enumeration
            answers = dns.resolver.resolve(self.target, 'A')
            for rdata in answers:
                self.results["subdomains"].append({
                    "domain": self.target,
                    "ip": rdata.address
                })
            
            # Try common subdomains
            common_subdomains = ["www", "mail", "ftp", "admin", "blog", "dev", "test"]
            for sub in common_subdomains:
                try:
                    subdomain = f"{sub}.{self.target}"
                    answers = dns.resolver.resolve(subdomain, 'A')
                    for rdata in answers:
                        self.results["subdomains"].append({
                            "domain": subdomain,
                            "ip": rdata.address
                        })
                except:
                    continue
        except Exception as e:
            print(f"[-] Error in subdomain scanning: {str(e)}")

    def scan_ports(self, host):
        """Scan common ports for open services"""
        print("[+] Starting port scan...")
        common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080, 8443]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    service = socket.getservbyport(port)
                    self.results["open_ports"].append({
                        "port": port,
                        "service": service
                    })
                sock.close()
            except:
                continue

    def analyze_headers(self, url):
        """Analyze HTTP headers for security issues"""
        print("[+] Analyzing HTTP headers...")
        try:
            response = requests.get(url, verify=False, timeout=10)
            headers = response.headers
            
            # Check for security headers
            security_headers = {
                "Strict-Transport-Security": False,
                "Content-Security-Policy": False,
                "X-Frame-Options": False,
                "X-XSS-Protection": False,
                "X-Content-Type-Options": False
            }
            
            for header in security_headers.keys():
                if header in headers:
                    security_headers[header] = True
                    
            self.results["headers_analysis"] = security_headers
            
            # Check for server information disclosure
            if "Server" in headers:
                self.results["headers_analysis"]["server_disclosure"] = headers["Server"]
                
        except Exception as e:
            print(f"[-] Error in header analysis: {str(e)}")

    def check_web_vulnerabilities(self, url):
        """Basic web vulnerability checks"""
        print("[+] Checking for common web vulnerabilities...")
        try:
            # Test for XSS reflection
            test_params = {"test": "<script>alert(1)</script>"}
            response = requests.get(url, params=test_params, verify=False, timeout=10)
            if test_params["test"] in response.text:
                self.results["web_vulnerabilities"].append({
                    "type": "Potential XSS",
                    "url": response.url
                })
            
            # Check for backup files
            common_backups = ["/backup.zip", "/backup.tar.gz", "/.git/config", "/wp-config.php.bak"]
            for backup in common_backups:
                try:
                    backup_url = url.rstrip('/') + backup
                    response = requests.head(backup_url, verify=False, timeout=5)
                    if response.status_code == 200:
                        self.results["web_vulnerabilities"].append({
                            "type": "Potential Backup File",
                            "url": backup_url
                        })
                except:
                    continue
                    
        except Exception as e:
            print(f"[-] Error in vulnerability check: {str(e)}")

    def save_results(self):
        """Save scan results to file"""
        if self.output_file:
            try:
                with open(self.output_file, 'w') as f:
                    json.dump(self.results, f, indent=4)
                print(f"[+] Results saved to {self.output_file}")
            except Exception as e:
                print(f"[-] Error saving results: {str(e)}")

    def run_scan(self):
        """Run all scanning modules"""
        print(f"[+] Starting security scan for {self.target}")
        
        # Parse URL for web checks
        if not self.target.startswith(('http://', 'https://')):
            url = f"https://{self.target}"
        else:
            url = self.target
            self.target = urlparse(url).netloc
        
        # Run all scans
        self.scan_subdomains()
        self.scan_ports(self.target)
        self.analyze_headers(url)
        self.check_web_vulnerabilities(url)
        
        # Save results
        self.save_results()
        
        print("[+] Scan complete!")
        return self.results

def main():
    parser = argparse.ArgumentParser(description='Security Scanner Tool')
    parser.add_argument('-t', '--target', required=True, help='Target domain or URL')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    args = parser.parse_args()

    scanner = SecurityScanner(args.target, args.output)
    results = scanner.run_scan()
    
    # Print summary
    print("\n=== Scan Summary ===")
    print(f"Target: {args.target}")
    print(f"Subdomains found: {len(results['subdomains'])}")
    print(f"Open ports: {len(results['open_ports'])}")
    print(f"Vulnerabilities found: {len(results['web_vulnerabilities'])}")
    
if __name__ == "__main__":
    main()

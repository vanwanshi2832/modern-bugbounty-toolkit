#!/usr/bin/python3

import argparse
import subprocess
import os
import json
import nmap
import requests
import concurrent.futures
from datetime import datetime
from colorama import Fore, Style, init

init()  # Initialize colorama

class ReplsScanner:
    def __init__(self, target, output_dir, threads=10):
        self.target = target
        self.output_dir = output_dir
        self.threads = threads
        self.author = "repls"
        self.version = "1.0.0"
        self.setup_directories()
        
    def setup_directories(self):
        """Create necessary directories for output"""
        directories = [
            self.output_dir,
            f"{self.output_dir}/ports",
            f"{self.output_dir}/vulns",
            f"{self.output_dir}/fuzzing",
            f"{self.output_dir}/reports"
        ]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            
    def print_banner(self):
        banner = f"""
        ╔══════════════════════════════════════════════╗
        ║             ReplsScanner {self.version}              ║
        ║         Advanced Security Scanner            ║
        ║              Created by: {self.author}             ║
        ║     https://github.com/{self.author.lower()}      ║
        ╚══════════════════════════════════════════════╝
        """
        print(Fore.CYAN + banner + Style.RESET_ALL)
        print(f"{Fore.YELLOW}[!] Starting scan on {self.target}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")

    def run_command(self, command):
        """Execute shell command and return output"""
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            stdout, stderr = process.communicate()
            return stdout
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to execute command: {command}{Style.RESET_ALL}")
            print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
            return None

    def port_scan(self):
        """Perform port scanning using nmap"""
        print(f"\n{Fore.GREEN}[+] Starting port scan...{Style.RESET_ALL}")
        
        # Quick TCP SYN scan
        print(f"{Fore.BLUE}[*] Running TCP SYN scan...{Style.RESET_ALL}")
        self.run_command(
            f"nmap -sS -T4 -p- {self.target} -oN {self.output_dir}/ports/tcp_scan.txt"
        )
        
        # Service version detection on open ports
        print(f"{Fore.BLUE}[*] Detecting service versions...{Style.RESET_ALL}")
        self.run_command(
            f"nmap -sV -sC -p$(grep ^[0-9] {self.output_dir}/ports/tcp_scan.txt | "
            f"cut -d'/' -f1 | tr '\\n' ',') {self.target} "
            f"-oN {self.output_dir}/ports/service_scan.txt"
        )

    def fuzz_directories(self):
        """Perform directory fuzzing using ffuf"""
        print(f"\n{Fore.GREEN}[+] Starting directory fuzzing...{Style.RESET_ALL}")
        wordlists = {
            "common": "/usr/share/wordlists/dirb/common.txt",
            "big": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        }
        
        for name, wordlist in wordlists.items():
            print(f"{Fore.BLUE}[*] Running {name} wordlist...{Style.RESET_ALL}")
            self.run_command(
                f"ffuf -w {wordlist} -u https://{self.target}/FUZZ "
                f"-o {self.output_dir}/fuzzing/{name}_paths.json"
            )

    def scan_vulnerabilities(self):
        """Scan for vulnerabilities using multiple tools"""
        print(f"\n{Fore.GREEN}[+] Scanning for vulnerabilities...{Style.RESET_ALL}")
        
        # Nikto scan
        print(f"{Fore.BLUE}[*] Running Nikto scan...{Style.RESET_ALL}")
        self.run_command(
            f"nikto -h {self.target} -output {self.output_dir}/vulns/nikto_scan.txt"
        )
        
        # Nuclei scan
        print(f"{Fore.BLUE}[*] Running Nuclei scan...{Style.RESET_ALL}")
        self.run_command(
            f"nuclei -u https://{self.target} -severity critical,high,medium "
            f"-o {self.output_dir}/vulns/nuclei_scan.txt"
        )

    def check_security_headers(self):
        """Check security headers of the target"""
        print(f"\n{Fore.GREEN}[+] Checking security headers...{Style.RESET_ALL}")
        
        try:
            response = requests.head(f"https://{self.target}", timeout=10)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS header',
                'Content-Security-Policy': 'Missing CSP header',
                'X-Frame-Options': 'Missing X-Frame-Options header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'X-XSS-Protection': 'Missing X-XSS-Protection header'
            }
            
            results = {}
            for header, message in security_headers.items():
                if header in headers:
                    results[header] = headers[header]
                else:
                    results[header] = message
                    
            with open(f"{self.output_dir}/vulns/security_headers.json", 'w') as f:
                json.dump(results, f, indent=4)
                
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to check security headers: {str(e)}{Style.RESET_ALL}")

    def generate_report(self):
        """Generate a comprehensive report"""
        print(f"\n{Fore.GREEN}[+] Generating report...{Style.RESET_ALL}")
        
        report = {
            "scan_info": {
                "scanner": f"ReplsScanner v{self.version}",
                "author": self.author,
                "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target": self.target
            },
            "port_scan": self.parse_nmap_results(),
            "vulnerabilities": self.parse_vulnerability_results(),
            "security_headers": self.read_json_file(f"{self.output_dir}/vulns/security_headers.json")
        }
        
        # Save JSON report
        with open(f"{self.output_dir}/reports/full_report.json", "w") as f:
            json.dump(report, f, indent=4)
        
        # Generate HTML report
        self.generate_html_report(report)

    def parse_nmap_results(self):
        """Parse nmap scan results"""
        try:
            with open(f"{self.output_dir}/ports/service_scan.txt", "r") as f:
                return {"raw_output": f.read()}
        except:
            return {"error": "No port scan results found"}

    def parse_vulnerability_results(self):
        """Parse vulnerability scan results"""
        results = {}
        
        # Parse Nuclei results
        try:
            with open(f"{self.output_dir}/vulns/nuclei_scan.txt", "r") as f:
                results["nuclei"] = f.readlines()
        except:
            results["nuclei"] = []
            
        # Parse Nikto results
        try:
            with open(f"{self.output_dir}/vulns/nikto_scan.txt", "r") as f:
                results["nikto"] = f.readlines()
        except:
            results["nikto"] = []
            
        return results

    def read_json_file(self, filepath):
        """Read JSON file contents"""
        try:
            with open(filepath, "r") as f:
                return json.load(f)
        except:
            return {}

    def generate_html_report(self, report_data):
        """Generate HTML report"""
        html_content = f"""
        <html>
            <head>
                <title>ReplsScanner Security Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .header {{ background-color: #333; color: white; padding: 20px; }}
                    .section {{ margin: 20px 0; padding: 20px; border: 1px solid #ddd; }}
                    .vulnerability {{ color: #d73a49; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>ReplsScanner Security Report</h1>
                    <p>Target: {report_data['scan_info']['target']}</p>
                    <p>Date: {report_data['scan_info']['scan_date']}</p>
                </div>
                <div class="section">
                    <h2>Security Headers</h2>
                    <pre>{json.dumps(report_data['security_headers'], indent=4)}</pre>
                </div>
                <div class="section">
                    <h2>Port Scan Results</h2>
                    <pre>{report_data['port_scan']['raw_output']}</pre>
                </div>
                <div class="section">
                    <h2>Vulnerabilities</h2>
                    <h3>Nuclei Findings</h3>
                    <pre>{''.join(report_data['vulnerabilities']['nuclei'])}</pre>
                    <h3>Nikto Findings</h3>
                    <pre>{''.join(report_data['vulnerabilities']['nikto'])}</pre>
                </div>
            </body>
        </html>
        """
        
        with open(f"{self.output_dir}/reports/report.html", "w") as f:
            f.write(html_content)

    def run_full_scan(self):
        """Run all scanning modules"""
        self.print_banner()
        self.port_scan()
        self.fuzz_directories()
        self.scan_vulnerabilities()
        self.check_security_headers()
        self.generate_report()
        print(f"\n{Fore.GREEN}[+] Scan completed! Check the output directory for results.{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}[*] Reports generated:{Style.RESET_ALL}")
        print(f"   - JSON Report: {self.output_dir}/reports/full_report.json")
        print(f"   - HTML Report: {self.output_dir}/reports/report.html")

def main():
    parser = argparse.ArgumentParser(
        description="ReplsScanner - Advanced Security Scanner by repls"
    )
    parser.add_argument("-t", "--target", required=True, help="Target host/domain")
    parser.add_argument("-o", "--output", default="output", help="Output directory")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads")
    args = parser.parse_args()

    scanner = ReplsScanner(args.target, args.output, args.threads)
    scanner.run_full_scan()

if __name__ == "__main__":
    main()

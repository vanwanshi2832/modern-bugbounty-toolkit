#!/usr/bin/python3

import argparse
import subprocess
import os
import json
import concurrent.futures
import requests
from datetime import datetime
from colorama import Fore, Style, init

init()  # Initialize colorama

class ReplsRecon:  # Class name changed to ReplsRecon
    def __init__(self, domain, output_dir):
        self.domain = domain
        self.output_dir = output_dir
        self.author = "repls"  # Author name changed to repls
        self.version = "1.0.0"
        self.setup_directories()
        
    def setup_directories(self):
        """Create necessary directories for output"""
        directories = [
            self.output_dir,
            f"{self.output_dir}/subdomains",
            f"{self.output_dir}/screenshots",
            f"{self.output_dir}/endpoints",
            f"{self.output_dir}/vulnerabilities",
            f"{self.output_dir}/reports"
        ]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            
    def print_banner(self):
        banner = f"""
        ╔══════════════════════════════════════════════╗
        ║               ReplsRecon {self.version}              ║
        ║          Advanced Recon Automation           ║
        ║              Created by: {self.author}             ║
        ║     https://github.com/{self.author.lower()}      ║
        ╚══════════════════════════════════════════════╝
        """
        print(Fore.CYAN + banner + Style.RESET_ALL)
        print(f"{Fore.YELLOW}[!] Starting scan on {self.domain}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")

    # [Middle part of code remains same...]

    def generate_report(self):
        """Generate a summary report"""
        print(f"\n{Fore.GREEN}[+] Generating report...{Style.RESET_ALL}")
        
        report = {
            "scan_info": {
                "scanner": f"ReplsRecon v{self.version}",  # Changed to ReplsRecon
                "author": self.author,
                "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target_domain": self.domain
            },
            "statistics": {
                "total_subdomains": len(self.read_file(f"{self.output_dir}/subdomains/all_subdomains.txt")),
                "live_hosts": len(self.read_file(f"{self.output_dir}/subdomains/live_hosts.txt")),
                "endpoints_found": len(self.read_file(f"{self.output_dir}/endpoints/gau_urls.txt"))
            },
            "vulnerability_summary": self.summarize_vulnerabilities()
        }
        
        # Save JSON report
        with open(f"{self.output_dir}/reports/summary.json", "w") as f:
            json.dump(report, f, indent=4)
            
        # Generate HTML report
        self.generate_html_report(report)

    def generate_html_report(self, report_data):
        """Generate HTML report"""
        html_content = f"""
        <html>
            <head>
                <title>ReplsRecon Scan Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .header {{ background-color: #333; color: white; padding: 20px; }}
                    .section {{ margin: 20px 0; padding: 20px; border: 1px solid #ddd; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>ReplsRecon Scan Report</h1>
                    <p>Generated by: {report_data['scan_info']['author']}</p>
                    <p>Date: {report_data['scan_info']['scan_date']}</p>
                </div>
                <div class="section">
                    <h2>Scan Statistics</h2>
                    <p>Total Subdomains: {report_data['statistics']['total_subdomains']}</p>
                    <p>Live Hosts: {report_data['statistics']['live_hosts']}</p>
                    <p>Endpoints Found: {report_data['statistics']['endpoints_found']}</p>
                </div>
            </body>
        </html>
        """
        
        with open(f"{self.output_dir}/reports/report.html", "w") as f:
            f.write(html_content)

def main():
    parser = argparse.ArgumentParser(
        description="ReplsRecon - Advanced Recon Automation Tool by repls"  # Changed description
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", default="output", help="Output directory")
    args = parser.parse_args()

    recon = ReplsRecon(args.domain, args.output)  # Changed to ReplsRecon
    recon.run_full_scan()

if __name__ == "__main__":
    main()

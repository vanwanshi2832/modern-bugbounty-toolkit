import requests
import socket
import ssl
import sys
import concurrent.futures
import json
from datetime import datetime
from typing import List, Dict, Any

class AdvancedSecurityScanner:
    def __init__(self, target: str):
        self.target = target
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'vulnerabilities': [],
            'headers': {},
            'ssl_info': {},
            'open_ports': [],
            'security_headers_missing': []
        }

    def check_security_headers(self) -> None:
        """Check for presence of important security headers"""
        try:
            response = requests.get(f"https://{self.target}")
            headers = response.headers
            self.results['headers'] = dict(headers)
            
            important_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Referrer-Policy'
            ]
            
            for header in important_headers:
                if header not in headers:
                    self.results['security_headers_missing'].append(header)
                    self.results['vulnerabilities'].append({
                        'type': 'missing_security_header',
                        'header': header,
                        'severity': 'Medium',
                        'description': f'Missing {header} security header'
                    })
        except Exception as e:
            self.results['vulnerabilities'].append({
                'type': 'connection_error',
                'severity': 'High',
                'description': f'Failed to connect: {str(e)}'
            })

    def check_ssl_configuration(self) -> None:
        """Check SSL/TLS configuration"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    self.results['ssl_info'] = {
                        'version': ssock.version(),
                        'cipher': ssock.cipher(),
                        'cert_expires': cert['notAfter']
                    }
                    
                    # Check for weak protocols
                    if 'TLSv1.1' in ssock.version() or 'TLSv1.0' in ssock.version():
                        self.results['vulnerabilities'].append({
                            'type': 'weak_ssl_protocol',
                            'severity': 'High',
                            'description': f'Weak SSL/TLS protocol in use: {ssock.version()}'
                        })
        except Exception as e:
            self.results['vulnerabilities'].append({
                'type': 'ssl_error',
                'severity': 'High',
                'description': f'SSL configuration error: {str(e)}'
            })

    def port_scan(self, ports: List[int]) -> None:
        """Scan common ports for open services"""
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((self.target, port))
                    if result == 0:
                        self.results['open_ports'].append(port)
                        if port not in [80, 443]:
                            self.results['vulnerabilities'].append({
                                'type': 'open_port',
                                'port': port,
                                'severity': 'Medium',
                                'description': f'Potentially unnecessary open port: {port}'
                            })
            except:
                continue

    def check_http_methods(self) -> None:
        """Check for dangerous HTTP methods"""
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'OPTIONS']
        
        for method in dangerous_methods:
            try:
                response = requests.request(method, f"https://{self.target}")
                if response.status_code != 405:  # Method Not Allowed
                    self.results['vulnerabilities'].append({
                        'type': 'dangerous_http_method',
                        'method': method,
                        'severity': 'High',
                        'description': f'Dangerous HTTP method {method} is enabled'
                    })
            except:
                continue

    def run_full_scan(self) -> Dict[str, Any]:
        """Run all security checks"""
        print(f"[*] Starting full security scan for {self.target}")
        
        # Run checks in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(self.check_security_headers),
                executor.submit(self.check_ssl_configuration),
                executor.submit(self.check_http_methods),
                executor.submit(self.port_scan, [20, 21, 22, 23, 25, 53, 80, 443, 8080, 8443])
            ]
            concurrent.futures.wait(futures)
        
        return self.results

    def save_report(self, filename: str) -> None:
        """Save scan results to a JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        print(f"[+] Report saved to {filename}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python advanced_security_scanner.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    scanner = AdvancedSecurityScanner(target)
    results = scanner.run_full_scan()
    
    # Print summary
    print("\n=== Scan Summary ===")
    print(f"Target: {target}")
    print(f"Total vulnerabilities found: {len(results['vulnerabilities'])}")
    print(f"Missing security headers: {len(results['security_headers_missing'])}")
    print(f"Open ports: {len(results['open_ports'])}")
    
    # Save detailed report
    scanner.save_report(f"security_scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

if __name__ == "__main__":
    main()

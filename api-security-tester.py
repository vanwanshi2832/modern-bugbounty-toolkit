#!/usr/bin/env python3

import argparse
import asyncio
import aiohttp
import json
import jwt
import random
import string
import sys
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs

class APISecurityTester:
    def __init__(self, target_url, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.session = None
        self.results = {
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": target_url,
            "vulnerabilities": [],
            "auth_issues": [],
            "rate_limit_status": None,
            "sensitive_data": [],
            "misconfigurations": [],
            "injection_points": []
        }
        
        # Common API paths to test
        self.common_paths = [
            "/api/v1/users",
            "/api/v1/admin",
            "/api/users",
            "/api/admin",
            "/api/auth",
            "/api/login",
            "/api/data",
            "/api/orders",
            "/api/products",
            "/api/settings"
        ]

    async def setup(self):
        """Initialize aiohttp session"""
        self.session = aiohttp.ClientSession()

    async def cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()

    def generate_jwt_tokens(self):
        """Generate various JWT tokens for testing"""
        tokens = []
        
        # Valid token
        valid_payload = {
            "sub": "test_user",
            "exp": datetime.utcnow() + timedelta(hours=1)
        }
        
        # Expired token
        expired_payload = {
            "sub": "test_user",
            "exp": datetime.utcnow() - timedelta(hours=1)
        }
        
        # Token without expiration
        no_exp_payload = {
            "sub": "test_user"
        }
        
        # Generate tokens with different signatures
        secret = "test_secret"
        tokens.append(("valid", jwt.encode(valid_payload, secret, algorithm='HS256')))
        tokens.append(("expired", jwt.encode(expired_payload, secret, algorithm='HS256')))
        tokens.append(("no_exp", jwt.encode(no_exp_payload, secret, algorithm='HS256')))
        tokens.append(("none_alg", jwt.encode(valid_payload, "", algorithm='none')))
        
        return tokens

    async def test_authentication_bypass(self):
        """Test various authentication bypass techniques"""
        print("[+] Testing authentication bypass scenarios...")
        
        # Headers to test
        headers_to_test = [
            {},  # No auth
            {"Authorization": "Bearer null"},
            {"Authorization": "Bearer undefined"},
            {"Authorization": "null"},
            {"X-API-Key": "null"},
            {"X-API-Key": ""}
        ]
        
        # Test JWT tokens
        jwt_tokens = self.generate_jwt_tokens()
        for token_type, token in jwt_tokens:
            headers_to_test.append({"Authorization": f"Bearer {token}"})
        
        for path in self.common_paths:
            url = urljoin(self.target_url, path)
            for headers in headers_to_test:
                try:
                    async with self.session.get(url, headers=headers) as response:
                        if response.status != 401 and response.status != 403:
                            self.results["auth_issues"].append({
                                "url": url,
                                "headers": headers,
                                "status": response.status,
                                "type": "Potential Auth Bypass"
                            })
                except Exception as e:
                    continue

    async def test_rate_limiting(self):
        """Test for rate limiting implementation"""
        print("[+] Testing rate limiting...")
        
        url = urljoin(self.target_url, "/api/v1/users")
        requests_count = 50
        
        start_time = time.time()
        responses = []
        
        for _ in range(requests_count):
            try:
                async with self.session.get(url) as response:
                    responses.append(response.status)
            except Exception:
                continue
        
        end_time = time.time()
        time_taken = end_time - start_time
        
        # Analyze responses
        if len(set(responses)) == 1 and time_taken < 5:  # All responses same and too fast
            self.results["rate_limit_status"] = {
                "status": "Potentially Missing",
                "requests": requests_count,
                "time_taken": time_taken,
                "unique_responses": len(set(responses))
            }

    async def test_injection_vulnerabilities(self):
        """Test for various injection vulnerabilities"""
        print("[+] Testing for injection vulnerabilities...")
        
        # Payloads to test
        injection_payloads = {
            "sql": ["' OR '1'='1", "admin'--", "1; DROP TABLE users"],
            "nosql": ['{"$gt": ""}', '{"$ne": null}'],
            "command": ["& ping 127.0.0.1", "; ls -la"],
            "xss": ["<script>alert(1)</script>", "javascript:alert(1)"]
        }
        
        for path in self.common_paths:
            url = urljoin(self.target_url, path)
            for injection_type, payloads in injection_payloads.items():
                for payload in payloads:
                    # Test in query parameters
                    params = {"q": payload, "search": payload, "id": payload}
                    try:
                        async with self.session.get(url, params=params) as response:
                            content = await response.text()
                            if any(error_sign in content.lower() for error_sign in 
                                ["error", "exception", "syntax", "mongodb", "mysql", "sqlite"]):
                                self.results["injection_points"].append({
                                    "url": url,
                                    "type": injection_type,
                                    "payload": payload,
                                    "location": "query"
                                })
                    except Exception:
                        continue
                    
                    # Test in JSON body
                    json_data = {"data": payload, "input": payload}
                    try:
                        async with self.session.post(url, json=json_data) as response:
                            content = await response.text()
                            if any(error_sign in content.lower() for error_sign in 
                                ["error", "exception", "syntax", "mongodb", "mysql", "sqlite"]):
                                self.results["injection_points"].append({
                                    "url": url,
                                    "type": injection_type,
                                    "payload": payload,
                                    "location": "body"
                                })
                    except Exception:
                        continue

    async def test_sensitive_data_exposure(self):
        """Test for sensitive data exposure"""
        print("[+] Testing for sensitive data exposure...")
        
        sensitive_patterns = {
            "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "credit_card": r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
            "api_key": r"[a-zA-Z0-9]{32,}",
            "password": r"password[\"':].*[\"']",
            "private_key": r"-----BEGIN.*PRIVATE KEY-----"
        }
        
        for path in self.common_paths:
            url = urljoin(self.target_url, path)
            try:
                async with self.session.get(url) as response:
                    content = await response.text()
                    try:
                        json_content = json.loads(content)
                        # Convert JSON to string for pattern matching
                        content = json.dumps(json_content)
                    except:
                        pass
                    
                    import re
                    for data_type, pattern in sensitive_patterns.items():
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            self.results["sensitive_data"].append({
                                "url": url,
                                "type": data_type,
                                "location": "response"
                            })
            except Exception:
                continue

    async def test_security_misconfigurations(self):
        """Test for common security misconfigurations"""
        print("[+] Testing for security misconfigurations...")
        
        # Test CORS configuration
        headers = {
            "Origin": "https://evil.com"
        }
        
        for path in self.common_paths:
            url = urljoin(self.target_url, path)
            try:
                async with self.session.options(url, headers=headers) as response:
                    cors_headers = response.headers
                    if "Access-Control-Allow-Origin" in cors_headers:
                        if cors_headers["Access-Control-Allow-Origin"] == "*" or \
                           cors_headers["Access-Control-Allow-Origin"] == "https://evil.com":
                            self.results["misconfigurations"].append({
                                "url": url,
                                "type": "CORS Misconfiguration",
                                "details": cors_headers
                            })
            except Exception:
                continue
            
        # Test security headers
        security_headers = [
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Content-Security-Policy",
            "Strict-Transport-Security"
        ]
        
        try:
            async with self.session.get(self.target_url) as response:
                missing_headers = [header for header in security_headers 
                                 if header not in response.headers]
                if missing_headers:
                    self.results["misconfigurations"].append({
                        "url": self.target_url,
                        "type": "Missing Security Headers",
                        "missing": missing_headers
                    })
        except Exception as e:
            print(f"[-] Error checking security headers: {str(e)}")

    def generate_report(self):
        """Generate detailed report of findings"""
        report = f"""
API Security Test Report
=======================
Target: {self.results['target']}
Scan Time: {self.results['scan_time']}

Summary:
--------
- Authentication Issues: {len(self.results['auth_issues'])}
- Injection Vulnerabilities: {len(self.results['injection_points'])}
- Sensitive Data Exposures: {len(self.results['sensitive_data'])}
- Security Misconfigurations: {len(self.results['misconfigurations'])}

Detailed Findings:
-----------------
1. Authentication Issues:
{json.dumps(self.results['auth_issues'], indent=2)}

2. Rate Limiting Status:
{json.dumps(self.results['rate_limit_status'], indent=2)}

3. Injection Points:
{json.dumps(self.results['injection_points'], indent=2)}

4. Sensitive Data Exposures:
{json.dumps(self.results['sensitive_data'], indent=2)}

5. Security Misconfigurations:
{json.dumps(self.results['misconfigurations'], indent=2)}

Recommendations:
---------------
1. Implement proper authentication and authorization
2. Add rate limiting if not present
3. Validate and sanitize all inputs
4. Encrypt sensitive data
5. Configure security headers
6. Implement proper CORS policies
"""
        
        if self.output_file:
            with open(self.output_file, 'w') as f:
                f.write(report)
            print(f"[+] Report saved to {self.output_file}")
        
        return report

async def main():
    parser = argparse.ArgumentParser(description='API Security Testing Tool')
    parser.add_argument('-t', '--target', required=True, help='Target API URL')
    parser.add_argument('-o', '--output', help='Output file for report')
    args = parser.parse_args()

    tester = APISecurityTester(args.target, args.output)
    
    try:
        await tester.setup()
        
        # Run all security tests
        await tester.test_authentication_bypass()
        await tester.test_rate_limiting()
        await tester.test_injection_vulnerabilities()
        await tester.test_sensitive_data_exposure()
        await tester.test_security_misconfigurations()
        
        # Generate and display report
        report = tester.generate_report()
        print(report)
        
    finally:
        await tester.cleanup()

if __name__ == "__main__":
    asyncio.run(main())

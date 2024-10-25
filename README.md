# Modern Bug Bounty Toolkit 2024 🛡️

A comprehensive collection of cutting-edge tools and resources for bug bounty hunting.

## 🔥 Active Reconnaissance Tools

### Subdomain Enumeration
- **Subfinder** - Fast passive subdomain enumeration
- **Amass** - In-depth Attack Surface Mapping
- **AssetFinder** - Domain & subdomain discovery
- **Findomain** - Cross-platform subdomain enumerator
- **SubDomainizer** - Tool for finding hidden subdomains
- **Sudomy** - Subdomain enumeration and analysis

### Content Discovery
- **katana** - Next-generation crawling and spidering
- **gau** - Get All URLs
- **ParamSpider** - Parameter discovery
- **gospider** - Fast web spider written in Go
- **hakrawler** - Simple, fast web crawler
- **waybackurls** - Fetch URLs from Wayback Machine

### Vulnerability Scanners
- **Nuclei** - Template-based scanning
- **Jaeles** - Automated Web Security Testing
- **cariddi** - Endpoints and secrets scanner
- **Arjun** - HTTP parameter discovery suite
- **XSStrike** - Advanced XSS detection
- **Corscanner** - CORS misconfiguration scanner
- **Dalfox** - Parameter analysis and XSS scanning
- **JWT_Tool** - JSON Web Token testing

### 🔒 Security Assessment Tools

### Web Application Testing
- **Burp Suite** - Web vulnerability scanner
- **OWASP ZAP** - Web app scanner
- **Wfuzz** - Web application fuzzer
- **SQLmap** - Automatic SQL injection
- **Commix** - Command injection exploiter
- **XXEinjector** - XXE vulnerability scanner

### Authentication Testing
- **OAuth-Tester** - OAuth vulnerability testing
- **JWT-Cracker** - JSON Web Token cracker
- **SSRFmap** - SSRF testing tool
- **Authz0** - Authorization testing tool

### 📱 Mobile Security
- **MobSF** - Mobile Security Testing Framework
- **Frida** - Dynamic instrumentation toolkit
- **Objection** - Runtime mobile exploration
- **apktool** - Android APK analysis
- **ios-analysis** - iOS app analysis toolkit
- **adb-toolkit** - Android debugging tools

### 🌐 Network Security
- **Nmap** - Network discovery and security scanning
- **Masscan** - Mass IP port scanner
- **RustScan** - Modern port scanner
- **BruteSpray** - Service credential bruteforcing

### 🔐 Cloud Security
- **CloudEnum** - Cloud infrastructure enumeration
- **S3Scanner** - Scan for open S3 buckets
- **AWS Recon** - AWS Security Scanning
- **CloudSploit** - Cloud security configuration scanner
- **GCPBucketBrute** - Google Cloud Storage scanner
- **AzureHound** - Azure security assessment

### 🤖 Automation Frameworks
- **Bug Bounty Recon Automation** - Custom scripts
- **Reconftw** - Simple recon workflow
- **Arsenal** - Multiple tools orchestration
- **Osmedeus** - Workflow engine for recon
- **Axiom** - Dynamic infrastructure framework

## 🚀 Quick Setup Script

```bash
#!/bin/bash

# Update system
sudo apt update && sudo apt upgrade -y

# Install basic dependencies
sudo apt install -y git python3 python3-pip golang ruby ruby-dev nmap masscan

# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/hahwul/dalfox/v2@latest

# Install Python tools
pip3 install droopescan webscreenshot arjun xsstrike jwt-tool

# Install Ruby tools
gem install wpscan

# Clone essential repositories
git clone https://github.com/OWASP/Amass.git
git clone https://github.com/maurosoria/dirsearch.git
git clone https://github.com/s0md3v/Corscanner.git
git clone https://github.com/swisskyrepo/SSRFmap.git
```

## 📚 Learning Resources
- Web Security Academy - Free, online web security training
- HackerOne CTF - Learn through challenges
- PentesterLab - Hands-on web hacking exercises
- PortSwigger Academy - Web security tutorials
- TryHackMe - Interactive cybersecurity learning
- HackTheBox - Penetration testing labs

## 🏆 Bug Bounty Platforms
- HackerOne
- Bugcrowd
- Intigriti
- YesWeHack
- Open Bug Bounty
- Synack Red Team

## 📝 Templates
- [Bug Report Template](templates/bug-report.md)
- [Responsible Disclosure Template](templates/disclosure.md)
- [POC Documentation Template](templates/poc.md)

## 🔄 Workflow Recommendations
1. Subdomain Enumeration → Content Discovery → Vulnerability Scanning
2. Manual Testing → Automated Scanning → Validation
3. Documentation → Reporting → Follow-up

## 🤝 Contributing
Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) before submitting a pull request.

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

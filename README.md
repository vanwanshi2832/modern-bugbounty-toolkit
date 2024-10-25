# Modern Bug Bounty Toolkit 🛡️

A curated collection of modern and actively maintained bug bounty tools and resources (2024)

## 🔥 Active Reconnaissance Tools

### Subdomain Enumeration
- [Subfinder](https://github.com/projectdiscovery/subfinder) - Fast passive subdomain enumeration
- [Amass](https://github.com/OWASP/Amass) - In-depth Attack Surface Mapping
- [AssetFinder](https://github.com/tomnomnom/assetfinder) - Domain & subdomain discovery

### Content Discovery
- [katana](https://github.com/projectdiscovery/katana) - Next-generation crawling and spidering
- [gau](https://github.com/lc/gau) - Get All URLs
- [ParamSpider](https://github.com/devanshbatham/ParamSpider) - Parameter discovery

### Vulnerability Scanners
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Template-based scanning
- [Jaeles](https://github.com/jaeles-project/jaeles) - Automated Web Security Testing
- [cariddi](https://github.com/edoardottt/cariddi) - Take a list of domains and scan for endpoints, secrets, and more

### API Security
- [APIKit](https://github.com/API-Security/APIKit) - API Security Tools Collection
- [Kiterunner](https://github.com/assetnote/kiterunner) - API Discovery
- [APIs Security Tools Collection](https://github.com/aravindsiv/api-security-tools) - Curated list of API security tools

## 🛠️ Automation Frameworks
- [Bug Bounty Recon Automation](https://github.com/yourname/bbrecon) - Custom automation scripts
- [Reconftw](https://github.com/six2dez/reconftw) - Simple recon workflow
- [Arsenal](https://github.com/Orange-Cyberdefense/arsenal) - Multiple tools orchestration

## 📱 Mobile Security
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - Mobile Security Testing Framework
- [Frida](https://github.com/frida/frida) - Dynamic instrumentation toolkit
- [Objection](https://github.com/sensepost/objection) - Runtime mobile exploration

## 🔐 Cloud Security
- [CloudEnum](https://github.com/initstring/cloud_enum) - Cloud infrastructure enumeration
- [S3Scanner](https://github.com/sa7mon/S3Scanner) - Scan for open S3 buckets
- [AWS Recon](https://github.com/darkbitio/aws-recon) - AWS Security Scanning

## 🚀 One-Click Setup Scripts
```bash
#!/bin/bash
# Install basic tools
apt update
apt install -y git python3 python3-pip golang

# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/tomnomnom/assetfinder@latest

# Install Python tools
pip3 install droopescan
pip3 install webscreenshot

# Clone repositories
git clone https://github.com/OWASP/Amass.git
git clone https://github.com/maurosoria/dirsearch.git
```

## 📚 Learning Resources
- [Web Security Academy](https://portswigger.net/web-security) - Free, online web security training
- [HackerOne CTF](https://ctf.hacker101.com/) - Learn through challenges
- [PentesterLab](https://pentesterlab.com/) - Hands-on web hacking exercises

## 🏆 Bug Bounty Platforms
- [HackerOne](https://hackerone.com/)
- [Bugcrowd](https://www.bugcrowd.com/)
- [Intigriti](https://www.intigriti.com/)

## 📝 Report Templates
- [Bug Report Template](templates/bug-report.md)
- [Responsible Disclosure Template](templates/disclosure.md)

## 🤝 Contributing
Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) before submitting a pull request.

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## ⭐ Support
If you found this helpful, please star the repository!

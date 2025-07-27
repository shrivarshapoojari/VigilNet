# 🛡️ VigilNet - Web and Network Security Analyzer

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An integrated, web-based cybersecurity tool that combines real-time packet sniffing, live host detection, web vulnerability scanning, network log analysis, and file security scanning — all in one lightweight and user-friendly dashboard.

## 📌 Project Overview

VigilNet is designed for small networks, personal systems, educational labs, and SOHO (Small Office/Home Office) setups. It bridges the gap between complex enterprise security tools and the need for simple, effective monitoring for everyday users. The tool provides a centralized dashboard where security analysts can perform comprehensive security assessments.

---

## 🚀 Core Features

### 🔍 **Web Vulnerability Scanner**
- **OWASP Top 10 Vulnerability Detection**:
  - SQL Injection testing
  - Cross-Site Scripting (XSS) - Reflected & Stored
  - Cross-Site Request Forgery (CSRF)
  - Command Injection detection
  - Insecure HTTP headers analysis
  - Directory traversal vulnerabilities
  - Session management flaws
- **Detailed Reporting**: Vulnerability severity, affected parameters, and remediation recommendations
- **Multiple Target Support**: Scan single URLs or multiple endpoints

### 📊 **Network Log Analyzer**
- **Multi-format Log Support**: Apache/Nginx access logs, UFW logs, custom JSON logs
- **Advanced Threat Detection**:
  - Failed login/brute force attempts
  - Port scanning detection
  - DoS attack pattern recognition
  - Suspicious IP identification with GeoIP lookup
  - Traffic anomaly detection
- **Analytics Dashboard**:
  - Top source IPs visualization
  - Most targeted ports analysis
  - Requests per second/minute metrics
  - Interactive timeline graphs
- **Export Capabilities**: Results exportable in multiple formats

### 🛡️ **Real-time Packet Analysis**
- **Live Packet Sniffing** using Scapy library
- **Protocol Analysis**: Deep inspection of network protocols
- **Traffic Monitoring**: Real-time network behavior analysis
- **Export Options**: Save captures in `.pcap` and `.txt` formats

### 🌐 **Active Host Discovery**
- **ARP-based Network Scanning**: Discover live hosts on the network
- **MAC Vendor Resolution**: Identify device manufacturers
- **Network Mapping**: Visual representation of network topology
- **Real-time Updates**: Live host status monitoring

### 🔒 **File Security Scanner**
- **Malware Detection**: Hash-based malware identification
- **File Quarantine System**: Isolate suspicious files
- **Multi-format Support**: Scan various file types
- **Threat Database Integration**: Uses comprehensive malware hash database

### 🔐 **Security Features**
- **User Authentication**: SHA-256 password hashing
- **Session Management**: Secure session handling
- **Access Control**: Role-based permissions
- **Data Protection**: Secure data storage and transmission

---

## 🛠️ Technology Stack

### **Backend Technologies**
- **Language**: Python 3.8+
- **Web Framework**: Flask with Blueprint architecture
- **Database**: SQLite with SQLAlchemy ORM
- **Security Libraries**: 
  - `scapy` for packet manipulation
  - `requests` & `beautifulsoup4` for web scanning
  - `mac-vendor-lookup` for hardware identification
  - `hashlib` for cryptographic operations

### **Frontend Technologies**
- **HTML5 & CSS3**: Modern responsive design
- **JavaScript**: Interactive dashboard functionality
- **Bootstrap 5**: Professional UI components
- **Chart.js**: Data visualization and analytics
- **Feather Icons**: Consistent iconography

### **Security & Analysis Libraries**
- **Network Analysis**: `scapy`, `socket`, `subprocess`
- **Web Security**: `urllib`, `re` (regex patterns)
- **Log Processing**: `pandas`, `json`, `re`
- **File Operations**: `os`, `hashlib`, `shutil`

---

## 📦 Installation & Setup

### **Prerequisites**
- Python 3.8 or higher
- Administrator/root privileges (required for packet sniffing)
- Git for repository cloning
- Virtual environment support

### **Step-by-Step Installation**

1. **Clone the Repository**
```bash
git clone https://github.com/shrivarshapoojari/VigilNet.git
cd VigilNet
```

2. **Set Up Virtual Environment**
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

3. **Install Network Scanner Module**
```bash
cd Network-Analyzer/Network-Scanner

# Download Malware Hash Database
# Note: Download from provided Google Drive link and place in Network-Scanner directory
# Link: https://drive.google.com/file/d/1eIM0yamYKjXTQ37XI-gwV2idRa0b4Zp2/view

# Install dependencies
pip install -r requirements.txt

# Start the Network Scanner service
python main.py
```

4. **Install Network Analyzer Module**
```bash
# Navigate to Network Analyzer
cd ../Network_Analysis

# Install dependencies
pip install -r requirements.txt

# Start the web interface
cd webVersion
python app.py
```

5. **Access the Application**
- **Main Dashboard**: http://127.0.0.1:8080
- **Advanced Scanner**: http://127.0.0.1:5000

---

## 🎯 Usage Guide

### **Dashboard Navigation**
The main interface provides access to all security modules:

- **Packet Capture**: `http://127.0.0.1:8080/capture`
- **Live Host Detection**: `http://127.0.0.1:8080/live-hosts`
- **Web Vulnerability Scanner**: `http://127.0.0.1:5000/scanner`
- **Network Log Analyzer**: `http://127.0.0.1:5000/analyzer`
- **File Scanner**: `http://127.0.0.1:5000/file_scan/scan_file`
- **Quarantine Management**: `http://127.0.0.1:5000/file_scan/open_quarantine`

### **Command Line Interface**
For advanced users, CLI options are available:

```bash
# Basic packet capture
python Main.py c --i eth0 --pc 100

# Filtered packet capture
python Main.py c --i eth0 --pc 100 --f "src host 192.168.1.1 and tcp"

# Live host detection
python Main.py lh --ip 192.168.1.104

# Advanced capture with multiple outputs
python Main.py c --i eth0 --pc 100 --s --t capture.txt --p capture.pcap
```

 
 

---

## 🎓 Academic Context

Developed as part of the **Network Programming and Security (NPS) Laboratory** coursework, this project demonstrates practical implementation of cybersecurity concepts including:

- Network protocol analysis
- Web application security testing
- Intrusion detection techniques
- Malware analysis fundamentals
- Security information and event management (SIEM)

---

## 🚀 Future Enhancements

- **Docker Containerization**: Easy deployment and scaling
- **REST API**: External integrations and automation
- **Advanced ML**: Machine learning-based anomaly detection
- **Reporting System**: Automated PDF/CSV report generation
- **Real-time Alerts**: Notification system for critical threats

---

**⚠️ Disclaimer**: This tool is designed for educational purposes and authorized security testing only. Users are responsible for ensuring compliance with applicable laws and regulations.

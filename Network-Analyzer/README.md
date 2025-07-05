# 🛡️ Packet Sniffer & Network Traffic Analyzer

An integrated, web-based cybersecurity tool that combines real-time packet sniffing, live host detection, web vulnerability scanning, and network log analysis — all in one lightweight and user-friendly dashboard.

## 📌 Project Overview

This tool is designed for small networks, personal systems, educational labs, and SOHO (Small Office/Home Office) setups. It aims to bridge the gap between complex enterprise tools and the need for simple, effective monitoring for everyday users.

---

## 🚀 Features

- **Live Packet Sniffing** using Scapy
- **Active Host Discovery** via ARP scan with MAC vendor resolution
- **Web Vulnerability Scanning** using HTTP inspection and BeautifulSoup
- **Network Log Analyzer** to detect anomalies
- **Secure User Authentication** with SHA-256 hashing
- **Data Export** in `.pcap` and `.txt` formats
- **Flask-based Web Interface** with real-time dashboard
- **SQLite** as lightweight backend storage

---

## 🛠️ Tech Stack

- **Language**: Python 3.8+
- **Framework**: Flask
- **Database**: SQLite
- **Frontend**: HTML, CSS, JavaScript
- **Libraries**:
  - `scapy`
  - `mac-vendor-lookup`
  - `requests`, `beautifulsoup4`
  - `flask`, `flask_sqlalchemy`
  - `hashlib`

---

## 📦 Installation

### Prerequisites

- Python 3.8+
- Admin/root privileges (for packet sniffing and ARP)
- Git

### Steps

```bash
# Clone the repository
git clone https://github.com/Shrinidhi-I/Network-Analyzer.git
cd Network-Analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Go to Network-Scanner
cd Network-Scanner
```
Add Malware Hash Database directory inside Network-Scanner:https://drive.google.com/file/d/1eIM0yamYKjXTQ37XI-gwV2idRa0b4Zp2/view?usp=sharing
```bash
# Install dependencies
pip install -r requirements.txt
# Run
python main.py
```
```bash
#Go to Network-Analyzer
cd Network-Analyzer
# Install dependencies
pip install -r requirements.txt
#Go to web Version
cd webVersion
# Run the Flask app
python app.py 
```
Open your browser and navigate to: http://127.0.0.1:8080

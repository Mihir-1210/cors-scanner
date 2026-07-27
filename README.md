# 🔍 CORS Misconfiguration Scanner

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-supported-brightgreen.svg)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Kali Linux](https://img.shields.io/badge/Kali-Linux-557C94.svg)](https://www.kali.org/)

A **blazing fast**, accurate CORS misconfiguration scanner that detects vulnerable CORS headers with detailed output. Shows exactly which headers are vulnerable (`Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, etc.) with color-coded severity levels. **Inspired by [of-cors](https://github.com/trufflesecurity/of-cors) but without Heroku dependency, making it fully self-hosted and faster.**

## ✨ Features

- 🚀 **High Performance**: Async I/O with configurable concurrency (50-200 requests/second)
- 🎯 **Accurate Detection**: Tests 100+ origin patterns including advanced bypass techniques
- 🎨 **Beautiful Output**: Color-coded by severity (🔴 Critical - Red, 🟠 High - Orange, 🔵 Medium - Dark Blue, 💠 Low - Light Blue)
- 📋 **Detailed Headers**: Shows exactly which CORS headers are vulnerable with values
- 🐳 **Docker Support**: One-command setup with Docker
- 📊 **Multiple Formats**: Console, JSON, CSV output options
- 🔧 **Self-Hosted**: No cloud dependencies, runs entirely locally
- ⚡ **Real-time Alerts**: Color-coded vulnerabilities displayed instantly during scan
- 📈 **Scan Statistics**: Severity breakdown with visual bar charts

## 🚀 One-Command Installation

```bash
git clone https://github.com/Mihir-1210/cors-scanner.git && cd cors-scanner && pip3 install -r requirements.txt && python3 scanner.py -u https://example.com
```

## Manual Setup
```bash
git clone https://github.com/Mihir-1210/cors-scanner.git
cd cors-scanner
pip3 install -r requirements.txt
python3 scanner.py -u https://example.com
```

## Docker Setup
```bash
docker build -t cors-scanner .
docker run --rm cors-scanner -u https://example.com
```

## 📖 Usage
Basic Scanning
```bash
# Scan single URL
python3 scanner.py -u https://example.com

# Scan multiple URLs from file (one per line)
python3 scanner.py -f urls.txt

# High concurrency scanning (100 concurrent requests)
python3 scanner.py -f urls.txt -c 100 -t 5

# Quiet mode (only show final results)
python3 scanner.py -f urls.txt -q
```

Docker Commands
```bash
# Scan single URL
docker run --rm cors-scanner -u https://example.com

# Scan from file (mount urls.txt)
docker run --rm -v $(pwd)/urls.txt:/app/urls.txt:ro cors-scanner -f urls.txt

# Save results to JSON file
docker run --rm -v $(pwd)/output:/app/output -v $(pwd)/urls.txt:/app/urls.txt:ro cors-scanner -f urls.txt -o /app/output/results.json -of json

# Scan from stdin
echo "https://example.com" | docker run --rm -i cors-scanner -stdin

# Using docker-compose
docker-compose up
```

Output Formats
```bash
# Console output (default) - Beautiful colored output with vulnerable headers highlighted
python3 scanner.py -u https://example.com

# JSON output - Structured data for automation
python3 scanner.py -u https://example.com -o results.json -of json

# CSV output - Easy import to spreadsheets
python3 scanner.py -u https://example.com -o results.csv -of csv
```

Advanced Options
```bash
# Enable SSL verification
python3 scanner.py -u https://example.com --verify-ssl

# Custom concurrency and timeout
python3 scanner.py -f urls.txt -c 200 -t 3

# Quiet mode with JSON output
python3 scanner.py -f urls.txt -q -o results.json -of json
```

## 📁 Project Structure
cors-scanner/
├── scanner.py              # Main scanner script with async I/O
├── requirements.txt        # Python dependencies (aiohttp, colorama, certifi)
├── Dockerfile             # Docker container configuration
├── docker-compose.yml     # Docker Compose for easy deployment
├── setup.sh               # One-command auto-setup script
├── LICENSE                # MIT License
├── README.md              # Documentation
└── wordlists/             # Origin test wordlists
    ├── common_origins.txt      # 100+ common origin patterns
    ├── focused_origins.txt     # Quick scan origins
    └── bypass_techniques.txt   # Advanced bypass techniques

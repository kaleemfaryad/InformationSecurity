# Packet Filtering Firewall

A Python-based network firewall with packet filtering capabilities, attack detection, and both GUI and CLI interfaces.

## Features

- 🛡️ **Real-time packet filtering** based on customizable rules
- 🔍 **Attack detection** with configurable thresholds
- 📊 **Interactive dashboard** showing traffic statistics
- 📝 **Rule management** with priority system
- 📂 **Comprehensive logging** of all network activity
- 🖥️ **Cross-platform** (Windows-focused with WinDivert)

## Installation

### Prerequisites

- Python 3.7 or higher
- Windows OS (for packet capture functionality)
- Administrator privileges

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/kaleemfaryad/InformationSecurity.git
   cd InformationSecurity

2. Install the requirements:
    pip install -r requirements.txt

3. Install Windivert from https://reqrypt.org/windivert.html
    place the sys lib and dll files inside x64 or x86 folders in the same folder as gui.py

4. Run the project
    open cmd as administrator
    cd path/to/InformationSecurity
    python gui.py






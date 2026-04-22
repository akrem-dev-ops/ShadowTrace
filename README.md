# 🌍 ShadowTrace v1.0
**Passive OSINT & Network Traffic Visualizer**

ShadowTrace is a powerful network packet sniffing and analysis tool. It captures live TCP/UDP traffic, performs geolocation lookups, and guesses the target's Operating System (OS Fingerprinting), all displayed on a real-time, interactive Cyberpunk-style dashboard.

## ✨ Key Features
- **Live Sniffing:** Real-time packet interception and analysis.
- **Interactive Map:** Visualizes target locations on a dynamic dark-mode map.
- **OS Fingerprinting:** Analyzes TTL and Window Size to identify the remote system.
- **Data Export:** Built-in functionality to export captured session data to CSV.
- **WebSocket Dashboard:** Seamless communication between the Python backend and the Web frontend.

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.x installed.
- **Windows Users:** Install [Npcap](https://npcap.com/) for packet capturing.

### 2. Installation
Clone the repository and install the required dependencies:
```bash
pip install -r requirements.txt
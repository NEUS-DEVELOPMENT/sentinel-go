# 📊 SysTelemetry Agent (Go)

# 📊 SysTelemetry Agent (Go)

[![Go Report Card](https://goreportcard.com/badge/github.com/NEUS-DEVELOPMENT/sentinel-go)](https://goreportcard.com/report/github.com/NEUS-DEVELOPMENT/sentinel-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/NEUS-DEVELOPMENT/sentinel-go/actions/workflows/build.yml/badge.svg)](https://github.com/NEUS-DEVELOPMENT/sentinel-go/actions)

**SysTelemetry Agent** is a lightweight, high-performance monitoring daemon written in Go...

**SysTelemetry Agent** is a lightweight, high-performance monitoring daemon written in Go. It is designed to collect system metrics (CPU, RAM, Disk, Uptime) from distributed nodes and report them to a central **SysTelemetry Gateway**.

Unlike heavy monitoring solutions, this agent is built for **minimal footprint** and **edge reliability**, capable of operating in unstable network environments with local caching.

---

## 🚀 Key Features

* **Low Overhead:** Written in pure Go, consuming <10MB RAM in typical operation.
* **Resilient Connectivity:** Automatically buffers metrics during network outages and syncs when connectivity is restored.
* **Remote Configuration:** Supports remote policy updates (poll interval, logging levels) via the Gateway API.
* **Secure Communication:** All traffic is encrypted via TLS/HTTPS.
* **Zero Dependencies:** compiles to a single static binary with no external library requirements.

---

## ⚙️ Architecture & Modes

### 🟢 Local Mode (Fallback)
If the Gateway is unreachable, the Agent switches to local heuristic monitoring.
* **Logic:** Uses local configuration rules.
* **Storage:** In-memory circular buffer.

### 🔵 Managed Mode (Default)
When connected to the Gateway:
* **Sync:** Pushes telemetry every 60s (configurable).
* **Updates:** Receives configuration patches securely signed by the server.
* **Cleanup:** Includes automated routines (`self-cleanup`) to remove configuration files upon uninstallation or revocation commands to ensure system hygiene.

---

## 📥 Installation

### Quick Start (Linux)
You can deploy the agent using the standard installer script:

```bash
curl -sL [https://your-app.onrender.com/install_agent.sh](https://your-app.onrender.com/install_agent.sh) | sudo bash

Manual Build
To build from source:

git clone [https://github.com/your-org/sys-telemetry-agent.git](https://github.com/your-org/sys-telemetry-agent.git)
cd sys-telemetry-agent
go build -ldflags="-s -w" -o agent main.go
./agent --url [https://your-gateway-url.com](https://your-gateway-url.com)

🔒 Security Note
​This agent is designed for enterprise environments. It supports Remote Revocation protocols, allowing administrators to remotely disable and uninstall agents from compromised or decommissioned nodes via the Gateway dashboard.
​📄 License
​MIT License. See LICENSE for details.
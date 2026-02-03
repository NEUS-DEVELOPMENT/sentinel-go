# 📊 SysTelemetry Agent (Go)

[![Go Report Card](https://goreportcard.com/badge/github.com/NEUS-DEVELOPMENT/sentinel-go)](https://goreportcard.com/report/github.com/NEUS-DEVELOPMENT/sentinel-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/NEUS-DEVELOPMENT/sentinel-go/actions/workflows/build.yml/badge.svg)](https://github.com/NEUS-DEVELOPMENT/sentinel-go/actions/workflows/build.yml)

**SysTelemetry Agent** is a lightweight, high-performance monitoring daemon written in Go. It is designed to collect system metrics (CPU, RAM, Disk, Uptime) from distributed nodes and report them to a central **SysTelemetry Gateway**.

Unlike heavy monitoring solutions, this agent is built for **minimal footprint** and **edge reliability**, capable of operating in unstable network environments with automatic retry and exponential backoff.

---

## 🚀 Key Features

* **Low Overhead:** Written in Go with minimal dependencies, consuming <10MB RAM in typical operation.
* **Real System Metrics:** Collects actual CPU usage, memory, disk usage (root partition), and uptime.
* **Resilient Connectivity:** Automatic retry with exponential backoff (up to 3 attempts) for network stability.
* **Remote Configuration:** Supports remote policy updates (poll interval, logging levels) via the Gateway API.
* **Secure Communication:** All traffic is encrypted via TLS/HTTPS with JWT signature verification.
* **Graceful Shutdown:** Handles SIGINT/SIGTERM signals for clean exit.
* **Production Ready:** Enhanced logging, error handling, and security hardening.

---

## 📊 Collected Metrics

The agent collects the following system metrics:

* **cpu_load** - Real-time CPU usage percentage (0-100%)
* **memory_usage** - Current memory allocation in MB
* **disk_usage** - Root partition disk usage percentage (0-100%)
* **uptime** - Agent uptime in seconds since start

---

## ⚙️ Architecture & Modes

### 🟢 Local Mode (Fallback)
If the Gateway is unreachable, the Agent continues collecting metrics locally.
* **Logic:** Uses local configuration rules.
* **Retry:** Automatic retry with exponential backoff on network failures.

### 🔵 Managed Mode (Default)
When connected to the Gateway:
* **Sync:** Pushes telemetry every 60s (configurable via `SYNC_INTERVAL` or remote updates).
* **Updates:** Receives configuration patches securely signed by the server.
* **Cleanup:** Includes automated routines to ensure clean system state.

---

## 📥 Installation

### Quick Start (Linux)
You can deploy the agent using the standard installer script:

```bash
curl -sL https://your-app.onrender.com/install_agent.sh | sudo bash
```

### Manual Build
To build from source:

```bash
git clone https://github.com/NEUS-DEVELOPMENT/sentinel-go.git
cd sentinel-go
go build -ldflags="-s -w" -o sentinel-agent main.go
```

### Environment Variables

**Required:**
* `APP_SECRET` - HMAC signing key for JWT verification (MUST be set in production)

**Optional:**
* `GATEWAY_URL` - Central server endpoint (default: https://your-app-name.onrender.com)
* `NODE_ID` - Unique agent identifier (default: node-{hostname})
* `SYNC_INTERVAL` - Telemetry sync frequency in seconds (default: 60)

### Running the Agent

```bash
export APP_SECRET="your-secure-secret-key"
export GATEWAY_URL="https://your-gateway.example.com"
export NODE_ID="production-node-01"
./sentinel-agent
```

---

## 🔒 Security Notes

**⚠️ IMPORTANT:** 
* The `APP_SECRET` environment variable **MUST** be set in production environments.
* Never use default or hardcoded secrets in production.
* The agent will refuse to start if `APP_SECRET` is not set, ensuring security by default.
* All communication with the Gateway is encrypted via HTTPS.
* Configuration updates are cryptographically verified using HS256 JWT signatures.

This agent is designed for enterprise environments and supports Remote Revocation protocols, allowing administrators to remotely disable and uninstall agents from compromised or decommissioned nodes via the Gateway dashboard.

---

## 🛠️ Development

### Running Tests

```bash
export APP_SECRET="test-secret"
go test -v ./...
```

### Building

```bash
go build -v -o sentinel-agent .
```

### Code Quality

```bash
go vet ./...
go fmt ./...
```

---

## 📄 License

MIT License. See LICENSE for details.
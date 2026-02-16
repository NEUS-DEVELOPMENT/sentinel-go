# SysTelemetry Agent
**High Performance Monitoring Daemon for Neus AI platform**

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Build Status](https://img.shields.io/github/actions/workflow/status/NEUS-DEVELOPMENT/sentinel-go/build.yml)

SysTelemetry Agent is a lightweight, high performance monitoring daemon written in Go. It is engineered to collect system metrics including CPU, RAM, Disk, and Uptime from distributed nodes and report them to a central SysTelemetry Gateway.

Unlike conventional monitoring solutions, this agent is built for minimal footprint and edge reliability. It is capable of operating in unstable network environments using local caching mechanisms.

---

## Key Features

* **Low Overhead**
Written in pure Go, consuming less than 10MB RAM during typical operation.

* **Resilient Connectivity**
Automatically buffers metrics during network outages and synchronizes data when connectivity is restored.

* **Remote Configuration**
Supports remote policy updates including poll intervals and logging levels via the Gateway API.

* **Secure Communication**
All traffic is encrypted via TLS and HTTPS protocols.

* **Zero Dependencies**
Compiles to a single static binary with no external library requirements for deployment.

---

## Architecture and Modes

### Local Mode Fallback
If the Gateway is unreachable, the Agent switches to local heuristic monitoring.
* **Logic**
Utilization of local configuration rules.
* **Storage**
In memory circular buffer management.

### Managed Mode
Default state when connected to the Gateway.
* **Synchronization**
Pushes telemetry every 60 seconds (configurable).
* **Updates**
Receives configuration patches securely signed by the server.
* **Cleanup**
Includes automated self cleanup routines to remove configuration files upon uninstallation or revocation commands.

---

## Installation

### Quick Start Linux
Deployment via the standard installer script.

```bash
curl -sL [https://matrix.neus-platform.io/install_agent.sh](https://matrix.neus-platform.io/install_agent.sh) | sudo bash

Manual Build
​To build from source:

git clone [https://github.com/NEUS-DEVELOPMENT/sys-telemetry-agent.git](https://github.com/NEUS-DEVELOPMENT/sys-telemetry-agent.git)
cd sys-telemetry-agent
go build -ldflags="-s -w" -o agent main.go
./agent --url [https://gateway.neus-platform.io](https://gateway.neus-platform.io)

Security Note
​This agent is designed for enterprise environments. It supports Remote Revocation protocols, allowing administrators to remotely disable and uninstall agents from compromised or decommissioned nodes via the Gateway dashboard.
​License
​MIT License. See LICENSE for details.
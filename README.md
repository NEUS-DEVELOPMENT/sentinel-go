# NEUS Sentinel Field Agent

[![Go Report Card](https://goreportcard.com/badge/github.com/neus-development/sentinel-go)](https://goreportcard.com/report/github.com/neus-development/sentinel-go)
[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![Coverage](https://img.shields.io/badge/Coverage-83.3%25-brightgreen.svg)](https://github.com/neus-development/sentinel-go)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A high-performance security proxy that protects LLM applications from prompt injection, jailbreaking, and adversarial attacks.

## 🏗️ Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  External LLM   │────▶│    SENTINEL     │────▶│      NEUS       │
│  (Client App)   │◀────│  (Local Proxy)  │◀────│   (Cloud AI)    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

Sentinel acts as a local security layer between your application and LLM providers, with optional cloud-based neural analysis from NEUS.

## 🔗 Connection Modes

| Mode | NEUS Connection | Use Case |
|------|-----------------|----------|
| **Offline** | ❌ No | Air-gapped environments, low latency requirements |
| **Connected** | ✅ Yes | Full protection with real-time threat intelligence |

**Default**: Free Tier (Offline mode) - no NEUS connection required.

**Failover**: If NEUS is unreachable, Sentinel continues with local rules (no blocking on connection failure).

## 🛡️ Features by Subscription Tier

| Feature | Free | Premium | Enterprise |
|---------|------|---------|------------|
| **NEUS Connection** | ❌ No | ✅ Yes | ✅ Yes |
| Static Regex Rules | ✅ | ✅ | ✅ |
| Hot-Patch Updates | ✅ | ✅ | ✅ |
| AES-256 Encryption | ✅ | ✅ | ✅ |
| RSA-2048 Key Exchange | ✅ | ✅ | ✅ |
| NEUS Neural Analysis | ❌ | ✅ | ✅ |
| Stealth Monitoring | ❌ | ✅ | ✅ |
| Custom Rules | ❌ | ❌ | ✅ |
| Priority Support | ❌ | ❌ | ✅ |
| Max Queries/Day | 1,000 | 100,000 | Unlimited |

## 🔒 Security Capabilities

### Without NEUS Connection (Free Tier / Offline)

| Capability | Status | Description |
|------------|--------|-------------|
| Static Rules | ✅ Active | Local regex-based pattern matching |
| Dynamic Rules | ✅ Active | Previously loaded hot-patches remain in memory |
| AES Encryption | ✅ Active | Local encryption for data protection |
| RSA Key Exchange | ✅ Active | Local key pair for secure handshakes |
| Neural Analysis | ❌ Inactive | Requires NEUS connection |
| Stealth Monitoring | ❌ Inactive | Requires Premium+ tier |
| Real-time Updates | ❌ Inactive | Requires NEUS connection |

### With NEUS Connection (Premium / Enterprise)

| Capability | Status | Description |
|------------|--------|-------------|
| Static Rules | ✅ Active | Local regex-based pattern matching |
| Dynamic Rules | ✅ Active | Real-time updates from NEUS |
| AES Encryption | ✅ Active | End-to-end encrypted tunnel |
| RSA Key Exchange | ✅ Active | Secure session establishment |
| Neural Analysis | ✅ Active | AI-powered threat detection |
| Stealth Monitoring | ✅ Active | Track and log bypass attempts |
| Real-time Updates | ✅ Active | Instant hot-patch deployment |
| Fingerprint Analysis | ✅ Active | Behavioral pattern detection |

## 🚀 Quick Start

```bash
# Build
go build -o sentinel.exe

# Run (Free tier - default)
./sentinel.exe

# Run with specific tier
SENTINEL_TIER=premium ./sentinel.exe
SENTINEL_TIER=enterprise ./sentinel.exe
```

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Server health and status |
| `/api/subscription` | GET | Subscription details |
| `/api/public_key` | GET | Get Sentinel's public key |
| `/api/key_exchange` | POST | Secure key exchange |
| `/api/hot_patch` | POST | Deploy new rules |
| `/api/bypass_log` | GET | Bypass attempts (Premium+) |
| `/api/upgrade` | POST | Upgrade subscription |

## 🧪 Testing

```bash
# Run all tests
go test -v

# Run with coverage
go test -cover

# Generate coverage report
go test -coverprofile=coverage.out
go tool cover -html=coverage.out
```

**Current Coverage: 83.3%** (35+ tests)

## 🔄 Failover Behavior

Sentinel is designed for resilience:

1. **NEUS Unavailable**: Falls back to local rules (no blocking)
2. **Invalid Response**: Logs warning, continues with local analysis
3. **Quota Exceeded**: Returns appropriate error without crashing

## 📦 Dependencies

- Go 1.21+
- No external dependencies (stdlib only)

## 🏛️ License

MIT License

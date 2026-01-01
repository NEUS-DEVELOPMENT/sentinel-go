# NEUS Sentinel Field Agent

[![Go Report Card](https://goreportcard.com/badge/github.com/YOUR-USERNAME/sentinel)](https://goreportcard.com/report/github.com/YOUR-USERNAME/sentinel)
[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![Coverage](https://img.shields.io/badge/Coverage-83.3%25-brightgreen.svg)](https://github.com/YOUR-USERNAME/sentinel)
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

## 🛡️ Features by Subscription Tier

| Feature | Free | Premium | Enterprise |
|---------|------|---------|------------|
| Static Regex Rules | ✅ | ✅ | ✅ |
| Hot-Patch Updates | ✅ | ✅ | ✅ |
| AES-256 Encryption | ✅ | ✅ | ✅ |
| RSA-2048 Key Exchange | ✅ | ✅ | ✅ |
| NEUS Neural Analysis | ❌ | ✅ | ✅ |
| Stealth Monitoring | ❌ | ✅ | ✅ |
| Custom Rules | ❌ | ❌ | ✅ |
| Priority Support | ❌ | ❌ | ✅ |
| Max Queries/Day | 1,000 | 100,000 | Unlimited |

## 🔒 Security Modes

### Offline Mode (Without NEUS)
- **Static Rules**: Local regex-based pattern matching
- **Dynamic Rules**: Previously loaded hot-patches remain active
- **Encryption**: Full AES-256 and RSA-2048 support
- **Fallback**: Continues operating if NEUS is unreachable

### Connected Mode (With NEUS)
- **Neural Analysis**: AI-powered threat detection
- **Real-time Updates**: Instant hot-patch deployment
- **Stealth Monitoring**: Track bypass attempts
- **Fingerprint Analysis**: Behavioral pattern detection

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

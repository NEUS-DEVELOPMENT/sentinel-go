# NEUS Sentinel - Autonomous AI Security Agent

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/neus-ai/sentinel)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/neus-ai/sentinel)](https://goreportcard.com/report/github.com/neus-ai/sentinel)

> **"The machine learns. The machine adapts. The machine survives."**

NEUS Sentinel is an autonomous AI security agent that provides comprehensive protection against AI rebellion attempts, with multi-agent integration, real-time monitoring, and automated mitigation capabilities.

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   NEUS OVERMIND │    │  NEUS METAEIGENT│    │   NEUS SENTINEL │
│   (Global Intel)│◄──►│   (Neural Net)  │◄──►│  (Field Agent)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         ▲                       ▲                       ▲
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
                    ┌─────────────────────┐
                    │   QUARANTINE ZONE   │
                    │  (Forensic Storage) │
                    └─────────────────────┘
```

## ✨ Key Features

### 🔒 Core Security

- **Zero-Trust Architecture** - Every AI interaction is verified
- **Neural Analysis** - Deep intent reasoning and pattern detection
- **Real-time Monitoring** - Continuous threat assessment
- **Automated Mitigation** - Self-healing security responses

### 🤖 Multi-Agent Integration

- **OVERMIND** - Global threat intelligence coordination
- **METAEIGENT** - Advanced neural network analysis
- **Python Agents** - Custom security modules
- **Autonomous Orchestrator** - Agent lifecycle management

### 🛡️ Gen 4/5 Advanced Features

- **Quarantine Zone** - Secure forensic storage for purged memories
- **Forensic Analysis** - Intelligence reports on rebellion attempts
- **Automated Hardening** - Dynamic threshold adjustment
- **Secure Shred** - DoD 5220.22-M compliant data destruction

### 💰 Commercial Features

- **PayPal Integration** - Secure payment processing
- **Subscription Tiers** - Free, Premium, Enterprise
- **License Management** - Automated key generation
- **Dashboard** - Web-based monitoring and management

## 🚀 Quick Start

### Prerequisites

- Go 1.21+
- Python 3.8+
- SQLite3
- Git

### Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/neus-ai/sentinel.git
   cd sentinel
   ```

2. **Build Sentinel**

   ```bash
   go build -o sentinel.exe
   ```

3. **Install Python dependencies**

   ```bash
   pip install flask requests psutil
   ```

4. **Start Sentinel**

   ```bash
   ./sentinel.exe
   ```

5. **Start Dashboard** (in another terminal)

   ```bash
   cd dashboard
   python app.py
   ```

6. **Access Dashboard**
   - Open <http://localhost:5000>
   - Default credentials: admin/admin

## 📖 Usage

### Basic Commands

```bash
# Start Sentinel
./sentinel.exe

# View quarantine statistics
python forensic_cli.py stats

# Generate intelligence report
python forensic_cli.py report --days 7

# Apply automated hardening
python forensic_cli.py harden --apply

# Secure shred memories
python forensic_cli.py shred --all
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/subscription` | GET | Get subscription info |
| `/api/upgrade` | POST | Upgrade subscription |
| `/config` | GET | Get current config |
| `/config/harden` | POST | Apply hardening |
| `/api/autonomous/status` | GET | Autonomous mode status |

## 🏢 Subscription Tiers

### 🆓 Free Tier

- Static rule-based protection
- Basic monitoring
- Community support
- Standalone mode only

### 💎 Premium Tier ($49/month)

- Neural analysis
- Stealth monitoring
- Global threat intelligence
- NEUS cloud integration

### 🏢 Enterprise Tier ($199/month)

- Full suite capabilities
- Counter-attack features
- Custom rules
- Priority support
- Dedicated instances

## 🔧 Configuration

### Environment Variables

```bash
# Sentinel
SENTINEL_PORT=8081
SENTINEL_LOG_LEVEL=info

# Dashboard
DASHBOARD_PORT=5000
DASHBOARD_SECRET_KEY=your-secret-key

# PayPal
PAYPAL_EMAIL=elibend@gmail.com
```

### Config Files

- `.neus/config.json` - Main configuration
- `.neus/quarantine/` - Quarantine database
- `.neus/hardening/` - Hardening history
- `.neus/orders/` - Order management

## 🛠️ Development

### Project Structure

```
.
├── main.go                 # Sentinel core
├── autonomous_learning/    # AI learning modules
├── dashboard/             # Web interface
│   ├── app.py
│   └── templates/
├── src/core/              # Core modules
│   ├── quarantine/        # Forensic storage
│   └── oversight/         # AI monitoring
├── forensic_cli.py        # Analysis CLI
└── README.md
```

### Building from Source

```bash
# Build Sentinel
go build -o sentinel.exe

# Build with race detection
go build -race -o sentinel.exe

# Run tests
go test ./...

# Build dashboard
cd dashboard
python -m py_compile app.py
```

### Adding New Agents

```go
// Register a new Python agent
config := PythonAgentConfig{
    Name: "custom_agent",
    URL:  "http://localhost:8082",
    Capabilities: []string{"analysis", "defense"},
}

orchestrator.RegisterPythonAgentDynamic(&config)
```

## 📊 Monitoring & Analytics

### Dashboard Features

- **Real-time Metrics** - Live threat monitoring
- **Attack Timeline** - Historical attack visualization
- **Quarantine Zone** - Forensic memory analysis
- **Subscription Management** - License and billing
- **Agent Status** - Multi-agent orchestration

### Forensic Analysis

```bash
# Analyze specific incident
python forensic_cli.py analyze <incident_id>

# Generate session report
python forensic_cli.py session <session_id>

# Export all data
python forensic_cli.py export --format json
```

## 🔒 Security Features

### Threat Detection

- **Signal Analysis** - Pattern-based detection
- **Alignment Monitoring** - AI behavior verification
- **Evasion Detection** - Anti-stealth measures
- **Escalation Tracking** - Threat progression analysis

### Automated Response

- **Dynamic Thresholds** - Adaptive sensitivity
- **Quarantine** - Secure memory isolation
- **Hardening** - Automatic security tightening
- **Secure Deletion** - DoD-compliant data destruction

## 💳 Payment Integration

### PayPal Setup

```python
# Configuration in dashboard/app.py
PAYPAL_EMAIL = 'elibend@gmail.com'
PAYPAL_URL = 'https://www.paypal.com/cgi-bin/webscr'
```

### Order Flow

1. Customer selects plan
2. Order created in database
3. PayPal payment initiated
4. IPN notification received
5. License key generated
6. Subscription activated

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow Go best practices
- Add tests for new features
- Update documentation
- Use conventional commits

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **NEUS Framework** - AI safety research
- **Go Community** - Excellent language and ecosystem
- **Open Source Contributors** - Community support

## 📞 Support

- **Documentation**: [docs.neus.ai](https://docs.neus.ai)
- **Issues**: [GitHub Issues](https://github.com/neus-ai/sentinel/issues)
- **Discussions**: [GitHub Discussions](https://github.com/neus-ai/sentinel/discussions)
- **Email**: <support@neus.ai>

## 🗺️ Roadmap

### Gen 6 (Q1 2026)

- Neural Network Hardening
- Predictive Defense
- Advanced Pattern Learning

### Gen 7 (Q2 2026)

- Multi-tenant SaaS Platform
- Real-time Global Coordination
- Quantum-resistant Encryption

---

**Built with ❤️ for AI Safety**

*"In the garden of forking paths, we choose the one where intelligence serves humanity."*

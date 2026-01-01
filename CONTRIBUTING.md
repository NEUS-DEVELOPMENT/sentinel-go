# Contributing to NEUS Sentinel 🛡️

First off, thank you for considering contributing to NEUS! It’s people like you who make NEUS Sentinel a world-class autonomous immune system.

By contributing, you help secure the future of AI.

## 🛡️ Our Security Philosophy
NEUS is built on **Sovereign Intelligence**. We prioritize:
1. **Performance:** Security logic must run in microseconds.
2. **Autonomy:** Modules should be effective even when offline.
3. **Stealth:** Protection logic should be ephemeral and hard to reverse-engineer.

## 🛠️ How Can You Help?

### 1. Adding Security Patterns (Rules)
If you discover a new Prompt Injection technique or a dangerous SQL pattern, you can add it to the `StaticRuleEngine`.
- Rules must be implemented as optimized Regular Expressions.
- Each rule must include a brief comment explaining the threat it mitigates.

### 2. Enhancing the Go Core
We are always looking to optimize the Sentinel's performance:
- Reducing memory allocations (GC pressure).
- Improving the `NeuralTunnel` encryption handshake.
- Enhancing the `HotPatch` atomic swapping mechanism.

### 3. Reporting Vulnerabilities
**Please do not open a public issue for security vulnerabilities.** If you find a bypass in the Sentinel, email us at `security@neus-logic.io`. We will coordinate a fix and credit you in the changelog.

## 🚀 Development Workflow

1. **Fork** the repository and create your branch from `main`.
2. **Install Go 1.21+** and ensure your environment is clean.
3. **Write Tests:** No contribution will be accepted without corresponding tests in `main_test.go`.
4. **Format:** Run `go fmt ./...` before committing.
5. **Lint:** Ensure your code passes `go vet`.

## 📜 Code of Conduct
By participating in this project, you agree to abide by our Code of Conduct: Be respectful, stay objective, and prioritize the safety of the AI ecosystem.

---
*NEUS Sentinel is a Generation 2 Security Solution. Let's build a sovereign future together.*

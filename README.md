# SafeAgent Sentinel

[![Go Report Card](https://goreportcard.com/badge/github.com/your-username/safeagent-sentinel)](https://goreportcard.com/report/github.com/your-username/safeagent-sentinel)

A secure proxy for AI inference requests with hot-patching capabilities.

## Features

- Static and dynamic rule engines for query filtering
- Atomic hot-patching of rules at runtime
- Encrypted communication with NEUS Logic Engine
- Buffer pooling for efficient tokenization

## Installation

```bash
go mod tidy
go build
```

## Testing

```bash
go test -v -cover
```

## License

MIT

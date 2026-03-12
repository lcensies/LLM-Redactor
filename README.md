# llm-prism

A local transparent proxy to redact secrets (API keys, PII) before they leave your machine.

| Feature | Direct Connection | With llm-prism |
| :--- | :--- | :--- |
| Data Privacy | Secrets sent to Cloud | Redacted locally |
| Provider Sees | `key: "sk-0a6916c7e8693709f204d8ad8d027634"` | `key: "[REDACTED]"` |
| Streaming | Standard | Real-time filtering |

## Core Features

- Automatic Redaction: Detects 100+ secret types using Gitleaks-compatible rules.
- Zero-Latency Streaming: Intercepts and filters SSE streams in real-time.
- Deep JSON Scanning: Recursively traverses nested structures (e.g., Anthropic content blocks).
- Local Audit: Records detected leaks to `llm-prism-detections.jsonl`.

## Quick Start

### Install

```bash
go install github.com/wangyihang/llm-prism@latest
```

### Run

```bash
llm-prism exec -- claude
```

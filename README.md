# LLM-Redactor

A local transparent proxy to redact secrets (API keys, PII) before they leave your machine.

| Feature | Direct Connection | With **LLM-Redactor** |
| :--- | :--- | :--- |
| Data Privacy | Secrets sent to Cloud | **Redacted locally** |
| Provider Sees | `Prompt: "Fix this: API_KEY=sk-123..."` | `Prompt: "Fix this: API_KEY=[REDACTED]"` |
| Streaming | Standard | **Real-time filtering** |

## Core Features

- Automatic Redaction: Detects 100+ secret types using Gitleaks-compatible rules.
- Zero Configuration: No need to modify your existing workflows.
- Zero-Latency Streaming: Intercepts and filters SSE streams in real-time.
- Deep JSON Scanning: Recursively traverses nested structures (e.g., Anthropic content blocks).
- Local Audit: Records detected leaks to `llm-redactor-detections.jsonl`.

## Quick Start

### Install

```bash
go install github.com/wangyihang/llm-redactor@latest
```

### Run

```bash
# Prepend `llm-redactor exec --` to your existing command (e.g., `claude`, `gemini`, `codex`).
llm-redactor exec -- claude
llm-redactor exec -- gemini
llm-redactor exec -- codex
```

### Exit

When you exit the ai coding agent, llm-redactor will output a brief summary of the detected leaks shows in the following figure, a secret key is detected and redacted for two times, all logs are stored in `llm-redactor-detections.jsonl`.

![Protected Request](./figures/02.png)

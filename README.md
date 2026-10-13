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
- Local Audit: Records detected leaks to `detections.jsonl`.


## Use Case 1: Execute Command with Redaction (Recommended)

This is the easiest way to use LLM-Redactor. Just prepend the command to your existing CLI tool. It will automatically set up the proxy and configure environment variables for the session.

### Install
```bash
go install github.com/wangyihang/llm-redactor/cmd/llm-redactor-exec@latest
```

### Usage
Prepend `llm-redactor-exec --` to your existing command:
```bash
llm-redactor-exec -- claude
llm-redactor-exec -- gemini
llm-redactor-exec -- codex
```

Upon exiting the session, a comprehensive audit summary will be displayed.

## Use Case 2: Standalone Redacting Proxy

Use this if you want to run a persistent proxy server that multiple tools or background processes can use.

### Install
```bash
go install github.com/wangyihang/llm-redactor/cmd/llm-redactor-proxy@latest
```

### Usage
1. Start the proxy server:
   ```bash
   llm-redactor-proxy --port 4000
   ```

2. Configure your environment or tools to use the proxy:
   ```bash
   export HTTP_PROXY=http://localhost:4000
   export HTTPS_PROXY=http://localhost:4000
   # Now run your tools normally
   claude
   ```

## Anonymization Examples

### Email Addresses

Email addresses are automatically detected and replaced with stable fake addresses generated for the session. The LLM's response is transparently unredacted before it reaches you, so you see real addresses in replies.

```
Input:  "Please review john.doe@acme-corp.com's PR"
Sent:   "Please review olivia.walker@example.net's PR"
Output: "Please review john.doe@acme-corp.com's PR"  ← restored automatically
```

### Git Repository URLs

Self-hosted Git repository URLs (HTTPS and SSH) are pseudonymized. The hostname, org, and repo name are each replaced with stable fakes. Responses referencing the fake URL are restored to the real one before display.

Public forges (github.com, gitlab.com, bitbucket.org, etc.) are **not** anonymized.

```
Input:  "git clone https://git.acme-internal.com/platform/auth-service.git"
Sent:   "git clone https://randomhost.io/fakeorg/fakeword.git"
Output: "git clone https://git.acme-internal.com/platform/auth-service.git"  ← restored

Input:  "git remote add origin git@git.acme-internal.com:platform/auth-service.git"
Sent:   "git remote add origin git@randomhost.io:fakeorg/fakeword.git"
Output: "git remote add origin git@git.acme-internal.com:platform/auth-service.git"  ← restored
```

### Phone Numbers

Phone numbers are detected and replaced with stable fake numbers, and restored
in responses. Covered: international numbers with a `+` country code, the
Russian trunk form (`8 (999) ...`), and grouped 10-digit numbers.

```
Input:  "client says call +7 999 123-45-67 or 8 (999) 765-43-21"
Sent:   "client says call +841017596283 or +812654103879"
Output: "client says call +7 999 123-45-67 or 8 (999) 765-43-21"  ← restored
```

Grouping is not preserved in the outbound request (every fake is a single
`+`-prefixed token), but the original string comes back verbatim. Bare
unseparated digit runs (`9991234567`), dotted forms (`555.123.4567`) and
extensions (`ext. 4`) are deliberately left alone: they collide with
timestamps, order ids, IP literals and version strings.

### VLESS / REALITY Proxy Configs

Pasting a proxy config in to debug it hands the model the credentials to your
server. The client `uuid`, the REALITY `public_key` and `short_id`, and the
SNI/host are pseudonymized in both JSON configs (Xray and sing-box key names)
and `vless://` share links. Responses are restored before you see them.

```
Input:  {"uuid":"3f1c9e2a-11b4-4c8d-9f77-0a1b2c3d4e5f","server_name":"www.microsoft.com","short_id":"0123abcd"}
Sent:   {"uuid":"1ef01f99-9c31-47e9-b6be-3762e6b83b53","server_name":"lhepxif.org","short_id":"a010ece7bf8d369a"}
Output: {"uuid":"3f1c9e2a-11b4-4c8d-9f77-0a1b2c3d4e5f","server_name":"www.microsoft.com","short_id":"0123abcd"}  ← restored

Input:  vless://3f1c9e2a-...-0a1b2c3d4e5f@vpn.example.org:443?pbk=AAECAwQF...&sid=0123abcd&sni=www.microsoft.com#MyNode
Sent:   vless://1ef01f99-...-3762e6b83b53@qmulxeb.net:443?pbk=MzSodfvk...&sid=a010ece7bf8d369a&sni=lhepxif.org#MyNode
```

The port, transport parameters and the `#label` fragment are left alone. IP
literals are handled by the IP pseudonymizer instead. A JSON `public_key` is
additionally matched by the Gitleaks `generic-api-key` rule, so it is masked
rather than restored — the real key still never leaves the machine.

### Company Names and Employee Names

These are not detected automatically. Add them to a custom rules file passed via `--redactor-rules` (TOML, Gitleaks-compatible format):

```toml
# ~/.acme-redactor.toml

[[rules]]
id = "company-name"
description = "Acme Corp brand name"
regex = "(?i)\\bacme[- ]corp\\b|\\bacme corporation\\b"
replace_engine = "company"   # replaced with a realistic fake company name

[[rules]]
id = "employee-name"
description = "Employee full names"
regex = "(?i)\\bjohn doe\\b|\\bjane smith\\b"
replace_engine = "name"      # replaced with a realistic fake person name

[[rules]]
id = "employee-email"
description = "Employee email addresses"
regex = "john\\.doe@acme\\.com|jane\\.smith@acme\\.com"
replace_engine = "email"     # replaced with a realistic fake email address
```

```bash
# exec mode
llm-redactor-exec --redactor-rules ~/.acme-redactor.toml -- claude

# proxy mode
llm-redactor-proxy --redactor-rules ~/.acme-redactor.toml --port 4000
```

The `replace_engine` field controls how matches are replaced:

| Value | Replacement | Example |
| :--- | :--- | :--- |
| *(omitted)* | `REDACTED_SECRET***` (one-way, same length) | `REDACTED_SECRET***` |
| `company` | Realistic fake company name (stable per session) | `"Acme Corp"` → `"Harrison Ltd"` |
| `name` | Realistic fake person name (stable per session) | `"John Doe"` → `"Emily Carter"` |
| `email` | Realistic fake email address (stable per session) | `"j@acme.com"` → `"x@example.net"` |
| `domain` | Fake domain name (stable per session) | `"vpn.acme.com"` → `"lhepxif.org"` |
| `uuid` | Fake UUID (stable per session) | `"3f1c9e2a-…"` → `"1ef01f99-…"` |
| `base64key` | Fake 43-char base64url key (stable per session) | `"AAECAwQF…"` → `"MzSodfvk…"` |
| `hex` | Fake 16-char hex string (stable per session) | `"0123abcd"` → `"a010ece7bf8d369a"` |
| `phone` | Fake E.164 phone number (stable per session) | `"+7 999 123-45-67"` → `"+841017596283"` |

When a `replace_engine` is set, the same real value always maps to the same fake value within a session, and the LLM's response is automatically unredacted before it reaches you.

A rule may also set `secret_group = N` to replace only capture group N instead of
the whole match — needed when the regex has to anchor on surrounding text:

```toml
[[rules]]
id = "internal-tenant-id"
regex = '"tenant_id"\s*:\s*"([0-9a-f]{16})"'
secret_group = 1             # rewrite the value, keep the JSON key intact
replace_engine = "hex"
```

## Audit & Logs

All detected leaks are logged to `detections.jsonl` with full metadata for post-session review.

![Summary](./figures/summary.png)

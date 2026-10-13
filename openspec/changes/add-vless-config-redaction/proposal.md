## Why

VLESS/REALITY proxy configs (Xray, sing-box, v2rayN) are routinely pasted into
LLM chats for debugging. They carry credentials that fully identify and grant
access to a private circumvention server: the client `uuid`, the REALITY
`public_key`, and the `short_id`. None of the existing detectors catch them —
a UUID is not a Gitleaks secret pattern, and a 43-char base64url key looks like
any other token. Today those values leave the machine verbatim.

## What Changes

- New always-on detector that pseudonymizes VLESS/REALITY config values in both
  JSON configs and `vless://` URIs, with stable, reversible fakes (responses are
  unredacted before reaching the user, like IP/email today).
- Redacted fields:
  - `uuid` / `id` (client UUID) → fake UUID
  - `public_key` / `publicKey` / `pbk` → fake 43-char base64url key
  - `short_id` / `shortId` / `sid` → fake hex string of the same length
  - `server_name` / `serverName` / `sni` → fake domain
  - `vless://<uuid>@<host>:<port>` → fake UUID + fake host
- `RegexRule` gains a `secret_group` field (mirrors Gitleaks' `secretGroup`):
  when set, only that capture group is replaced, so key-anchored patterns like
  `"short_id": "abcd"` can rewrite the value without destroying the JSON key.
  Existing rules (group 0 / whole match) are unaffected.
- Three new `replace_engine` values usable from user config too: `uuid`,
  `base64key`, `hex`.

Non-goals: generic `"server"` / `"address"` JSON keys (too ambiguous to key off
safely — IP literals are already handled by the IP detector), and the
`vless://` URI fragment/label.

## Capabilities

### New Capabilities
- `vless-config-redaction`: detection, pseudonymization and reversal of
  VLESS/REALITY proxy config credentials in requests and responses.

### Modified Capabilities
<!-- none: openspec/specs/ is empty, no existing spec's requirements change -->

## Impact

- `pkg/redactor/detectors/vless.go` (new): rule set + constructor.
- `pkg/redactor/detectors/regex.go`: honor `SecretGroup` in Redact.
- `pkg/redactor/detectors/replace_engine.go`: `uuid`, `base64key`, `hex` engines.
- `pkg/redactor/rules.go`: `SecretGroup` on `Rule`, plumbed into `RegexRule`.
- `pkg/redactor/redactor.go`: register the detector in `New`.
- No new dependencies (`go-faker` and stdlib `crypto/rand` suffice).
- Detection stats/audit log gain a `vless` detector type.

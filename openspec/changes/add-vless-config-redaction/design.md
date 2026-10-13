## Context

`Redactor.New` builds a fixed detector list: a `RegexDetector` over the loaded
Gitleaks/TOML rules, plus always-on `DeepSeek`, `IP`, `Email` and `GitProject`
detectors. Reversible detectors implement `Unredactor`; `UnredactContent` runs
them over responses and over the streaming reader.

`RegexDetector` already does everything a VLESS rule set needs — keyword
prefilter, `replace_engine` pseudonymizers keyed per engine, stable
`realToFake`/`fakeToReal` maps, and a longest-fake-first `Unredact`. It has one
gap: `Regex.ReplaceAllStringFunc` replaces the **whole match**, so a
key-anchored pattern like `"short_id"\s*:\s*"([0-9a-f]{2,16})"` would delete the
JSON key along with the value. Key anchoring is mandatory here: a bare
`[0-9a-f]{2,16}` or bare 43-char base64url pattern would fire on half the
traffic.

## Goals / Non-Goals

**Goals:**
- Never let a VLESS `uuid`, REALITY `public_key`/`short_id`, or the SNI/host of
  a private node leave the machine.
- Reuse `RegexDetector` rather than write a new detector engine.
- Round-trip: fakes restore to real values in responses and SSE streams.

**Non-Goals:**
- Generic `"server"` / `"address"` JSON keys. Too common to key off; IP literals
  are already covered by the IP detector.
- Parsing/validating VLESS configs. Regex only — a malformed config that still
  contains a UUID is redacted, one that does not is not our problem.
- User-configurable field lists. The rules ship built in; the new
  `replace_engine` values are available in user config if someone wants more.

## Decisions

### 1. Built-in rule set fed to a `RegexDetector`, not a new detector type

`NewVLESSDetector()` returns a `*RegexDetector` constructed from a package-level
rule slice, appended to `detectorsList` in `Redactor.New`. Zero new
redact/unredact logic, and `Unredact` comes free.

`RegexDetector` gets an unexported `typeName` field (default `"regex"`) so the
VLESS instance reports `Type() == "vless"` and its detections are counted
separately in stats/audit. Alternative — reporting `"regex"` — merges VLESS
counts into the Gitleaks bucket and makes the audit log ambiguous.

### 2. `SecretGroup` on the rule, mirroring Gitleaks' `secretGroup`

`RegexRule.SecretGroup int` (TOML/JSON `secret_group`). In `Redact`, rules with
`SecretGroup > 0` take a submatch path built on `FindAllStringSubmatchIndex`
plus a manual rebuild of the string; rules with `0` keep the existing
`ReplaceAllStringFunc` path untouched.

Rejected: "replace group 1 automatically when the regex has one". Many Gitleaks
rules have capture groups and currently rely on whole-match replacement — that
would silently change their behavior.

If the group did not participate in a match (`idx[2*g] < 0`) or the index is out
of range, the match is emitted unchanged and no callback fires.

### 3. Rules (all with `SecretGroup = 1`, all case-insensitive)

Keywords are set so the prefilter skips these rules on ordinary traffic.

| id | keywords | regex | engine |
|---|---|---|---|
| `vless-uuid` | uuid, "id" | `"(?:uuid\|id)"\s*:\s*"(<UUID>)"` | `uuid` |
| `vless-public-key` | public_key, publickey, pbk | `"(?:public_key\|publicKey\|pbk)"\s*:\s*"([A-Za-z0-9_-]{43})"` | `base64key` |
| `vless-short-id` | short_id, shortid, sid | `"(?:short_id\|shortId\|sid)"\s*:\s*"([0-9a-f]{2,16})"` | `hex` |
| `vless-sni` | server_name, servername, sni | `"(?:server_name\|serverName\|sni)"\s*:\s*"(<HOST>)"` | `domain` |
| `vless-uri-uuid` | vless:// | `vless://(<UUID>)@` | `uuid` |
| `vless-uri-host` | vless:// | `vless://<UUID>@(<HOST>)` | `domain` |
| `vless-uri-pbk` | pbk= | `[?&](?:pbk\|publicKey)=([A-Za-z0-9_-]{43})` | `base64key` |
| `vless-uri-sid` | sid= | `[?&](?:sid\|shortId)=([0-9a-f]{2,16})` | `hex` |
| `vless-uri-sni` | sni= | `[?&]sni=(<HOST>)` | `domain` |

`<UUID>` = `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
`<HOST>` = `[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+`.

Rule order matters for the URI pair: `vless-uri-uuid` runs first and its fake is
also UUID-shaped, so `vless-uri-host` still matches afterwards.

`"id"` is broad, but the UUID shape constrains it; `"id": "msg_01…"` and numeric
ids do not match. Anthropic/OpenAI request ids are not bare UUIDs.

### 4. Three new replace engines, minimum fake length 16

Added to `ReplaceEnginePseudonymizer.GetOrCreate`:
- `uuid` → `faker.UUIDHyphenated()` (36 chars)
- `base64key` → 32 random bytes, `base64.RawURLEncoding` → exactly 43 chars,
  the x25519 public-key shape REALITY uses
- `hex` → **always 16 hex chars**, independent of the real value's length
- `domain` → `faker.DomainName()` (reuses the existing engine style; the
  GitProject detector already does this for hosts)

The 16-char floor for `hex` is a correctness requirement, not cosmetics.
`RegexDetector.Unredact` restores by `strings.ReplaceAll` over whole response
bodies. A 2-char fake like `3f` would rewrite arbitrary unrelated text — the
same class of bug as the IPv6 `::` false positive already fixed in `ip.go`. A
16-char random hex string effectively cannot collide. VLESS accepts short_ids
of any even length ≤ 16, so a length change costs nothing downstream (the fake
is never used to connect anywhere).

Randomness comes from `crypto/rand`; `math/rand` is already imported in that
file for company suffixes, but keys should not be predictable from a seed.

## Risks / Trade-offs

- **`"id"` UUID rule fires on non-VLESS UUIDs** (session ids, tool ids) →
  Accepted. Replacement is stable and reversible, so a UUID swapped in the
  request is swapped back in the response; the model sees a consistent
  identifier either way. This is exactly how the IP and email detectors behave.
- **`sid`/`pbk` query-param rules are not VLESS-specific** — `[?&]sid=` appears
  in unrelated URLs → Mitigated by the hex length bound (2–16, even-ish) and by
  the fact that a swapped tracking parameter is restored on the way back. Rule
  ids make it greppable in `detections.jsonl` if it becomes noisy.
- **Gitleaks `generic-api-key` claims JSON `public_key` values** — it runs after
  this detector and masks the pseudonym with `REDACTED_SECRET***`, so a JSON
  public key is not restorable (the `vless://…?pbk=` form is, since `pbk` is not
  a gitleaks secret keyword) → Accepted, and covered by a test. The real key
  never leaves either way; ordering cannot help because the last detector to run
  wins, and any ≥10-char value under a `*_key` key matches that rule.
- **Schema subtrees / signed thinking blocks** → No new handling needed:
  `redactValueJSON` already skips JSON Schema payloads and signed assistant
  thinking blocks before any detector sees the string.
- **Fake length differs from real length** (16-char hex, 43-char key) →
  Body is re-marshalled anyway (`RedactRequest`), and `Content-Length` is
  recomputed by the proxy, as it already is for email/git pseudonyms.
- **A model asked to "fix this config" returns a fake it mutated** (e.g.
  truncates the key) → It no longer matches the `fakeToReal` table and is not
  restored. Pre-existing limitation of every pseudonymizing detector here.

## Open Questions

- Should `vless://` URIs also have their `#fragment` label redacted? It often
  names the country/provider. Left alone for now — it is free text, not a
  credential, and a `domain`-style fake would read oddly.

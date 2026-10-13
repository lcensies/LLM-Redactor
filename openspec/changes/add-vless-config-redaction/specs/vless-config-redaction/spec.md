## ADDED Requirements

### Requirement: VLESS JSON config credentials are pseudonymized
The redactor SHALL replace VLESS/REALITY credential values found in JSON
configs with stable fake values of the same syntactic shape, leaving the
surrounding JSON key and structure intact. The affected keys are
`uuid`/`id` (UUID-shaped values only), `public_key`/`publicKey`/`pbk`,
`short_id`/`shortId`/`sid`, and `server_name`/`serverName`/`sni`.

#### Scenario: sing-box VLESS outbound
- **WHEN** a request body contains `"uuid": "3f1c9e2a-11b4-4c8d-9f77-0a1b2c3d4e5f"`, `"public_key": "xN1Yq8QK0oJ3bV7sT2wA9cLpR4mZ6dH5uE1gF0iK7jY"` and `"short_id": "0123abcd"`
- **THEN** each value is replaced by a fake of the same kind (fake UUID, fake 43-char base64url key, fake hex string)
- **AND** the JSON keys, quoting and nesting are unchanged and the body still parses as JSON

#### Scenario: Xray camelCase keys
- **WHEN** a config uses `"id"`, `"publicKey"`, `"shortId"` and `"serverName"`
- **THEN** those values are pseudonymized exactly as their snake_case equivalents

#### Scenario: Non-UUID id values are untouched
- **WHEN** a body contains `"id": "msg_01ABC"` or `"id": 42`
- **THEN** the value is left unchanged, because it does not match the UUID shape

### Requirement: vless:// URI credentials are pseudonymized
The redactor SHALL pseudonymize the UUID, host, `pbk`, `sid` and `sni`
components of a `vless://` URI. The scheme, port, remaining query parameters
and the URI fragment SHALL be preserved.

#### Scenario: Full REALITY share link
- **WHEN** content contains `vless://3f1c9e2a-11b4-4c8d-9f77-0a1b2c3d4e5f@vpn.example.org:443?security=reality&pbk=xN1Yq8QK0oJ3bV7sT2wA9cLpR4mZ6dH5uE1gF0iK7jY&sid=0123abcd&sni=www.microsoft.com&type=tcp#MyNode`
- **THEN** the UUID, host, `pbk`, `sid` and `sni` values are replaced by fakes
- **AND** `vless://`, `:443`, `security=reality`, `type=tcp` and `#MyNode` are unchanged

### Requirement: Pseudonyms are stable and reversible
Each real value SHALL map to exactly one fake for the lifetime of the process,
and the same fake SHALL map back to that real value. Responses (including
streamed responses) SHALL be unredacted so the user sees the original values.

#### Scenario: Same value twice
- **WHEN** the same UUID appears in two different requests in one session
- **THEN** both are replaced by the identical fake UUID

#### Scenario: Model echoes a redacted config back
- **WHEN** a response body or SSE stream contains the fake UUID, fake public key, fake short id or fake SNI
- **THEN** the original values are restored before the response reaches the client

#### Scenario: Value also matched by a Gitleaks secret rule
- **WHEN** a value is pseudonymized here and a Gitleaks rule matches the result
  (a JSON `"public_key"` matches `generic-api-key`, which runs after this detector)
- **THEN** the Gitleaks mask wins and the value is not restorable
- **AND** the real value still never leaves the machine

### Requirement: Fakes are long enough for safe reverse substitution
Generated fakes SHALL be at least 16 characters long regardless of the length
of the real value, so that restoring them by substring replacement cannot
corrupt unrelated response text.

#### Scenario: Two-character short_id
- **WHEN** a config contains `"short_id": "ab"`
- **THEN** the fake written to the outbound request is a 16-character hex string
- **AND** unredacting a response restores `ab` only where that 16-character fake appears

### Requirement: Rules may target a capture group
A regex redaction rule SHALL support a `secret_group` field: when it is greater
than zero, only that capture group of each match is replaced and the rest of
the match is preserved. When it is absent or zero, the whole match is replaced,
as today.

#### Scenario: Key-anchored rule
- **WHEN** a rule with regex `"short_id"\s*:\s*"([0-9a-f]{2,16})"` and `secret_group = 1` matches `"short_id": "0123abcd"`
- **THEN** only `0123abcd` is replaced and `"short_id": "` remains

#### Scenario: Existing whole-match rules unaffected
- **WHEN** a rule without `secret_group` matches
- **THEN** the entire match is replaced, exactly as before this change

#### Scenario: Group did not participate in the match
- **WHEN** the configured group index is out of range or the group did not participate in a given match
- **THEN** the match is left unchanged and no detection is recorded

### Requirement: Detections are audited
Every VLESS value replacement SHALL emit a detection event with a `vless`
detector type and the rule id that matched, using the existing masked-content
audit path.

#### Scenario: Audit entry for a redacted uuid
- **WHEN** a VLESS uuid is redacted
- **THEN** `detections.jsonl` gains an entry with `detector_type: "vless"`, the rule id, and the masked value
- **AND** the summary counts it under the `vless` detector

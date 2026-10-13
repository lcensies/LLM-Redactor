## 1. Capture-group support in RegexDetector [sequential]

- [x] 1.1 Add `SecretGroup int` to `redactor.Rule` (`toml:"secret_group" json:"secret_group"`) and to `detectors.RegexRule`; copy it through in `Redactor.New`
- [x] 1.2 In `RegexDetector.Redact`, add a submatch path used when `rule.SecretGroup > 0`: walk `FindAllStringSubmatchIndex`, rewrite only that group's span, leave the match untouched (and fire no callback) when the group index is out of range or did not participate
- [x] 1.3 Add `typeName` field to `RegexDetector` (default `"regex"`) plus a constructor that sets it; `Type()` returns it
- [x] 1.4 Tests in `regex_test.go`: group-1 rule rewrites only the value; existing no-group rule still replaces the whole match; non-participating group is a no-op; `replace_engine` + `SecretGroup` round-trips through `Unredact`

## 2. Replace engines [sequential]

- [x] 2.1 Add `uuid`, `base64key`, `hex` and `domain` cases to `ReplaceEnginePseudonymizer.GetOrCreate` — `faker.UUIDHyphenated()`, 32 `crypto/rand` bytes as `base64.RawURLEncoding` (43 chars), 16 hex chars from `crypto/rand`, `faker.DomainName()`
- [x] 2.2 Test in `replace_engine_test.go`: each engine yields the expected shape/length, is stable per real value, unique per distinct value, and `Restore` inverts it; assert the `hex` fake is 16 chars even for a 2-char input

## 3. VLESS rule set [sequential]

- [x] 3.1 Create `pkg/redactor/detectors/vless.go` with the nine rules from design.md §3 (shared `<UUID>`/`<HOST>` fragments, keywords set, `SecretGroup: 1`) and `NewVLESSDetector() *RegexDetector`
- [x] 3.2 Register `detectors.NewVLESSDetector()` in the `detectorsList` in `Redactor.New`
- [x] 3.3 Verify every rule compiles under RE2 (no lookaround) — a table test that ranges over the rule slice

## 4. Behavior tests [parallel]

- [x] 4.1 `vless_test.go`: sing-box JSON (`uuid`/`public_key`/`short_id`/`server_name`) and Xray camelCase JSON — values replaced, keys intact, output still parses as JSON, no real value survives anywhere in the output
- [x] 4.2 `vless_test.go`: full `vless://` share link — uuid, host, `pbk`, `sid`, `sni` replaced; scheme, port, `security=reality`, `type=tcp` and `#MyNode` preserved
- [x] 4.3 `vless_test.go`: negative cases — `"id": "msg_01ABC"`, `"id": 42`, a 43-char token under an unrelated key, and a UUID-free config are all unchanged
- [x] 4.4 `vless_test.go`: stability and reversal — same value twice yields the same fake; `Unredact` of the redacted output restores the original exactly {needs: 4.1, 4.2}
- [x] 4.5 `redactor_test.go`: end-to-end `RedactRequest` + `UnredactResponse` on a VLESS config body, and one SSE-style stream through `WrapStreamUnredactor` that carries the fake uuid

## 5. Wrap-up [sequential]

- [x] 5.1 `go test ./...` green; `go vet ./...` clean
- [x] 5.2 Add a "VLESS / REALITY proxy configs" example to the Anonymization Examples section of `README.md` (before/after, noting responses are restored)

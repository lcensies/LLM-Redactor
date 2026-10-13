## Why

Phone numbers are the one piece of direct personal data that gets pasted into
LLM chats constantly — in logs, CRM rows, support tickets, contact blocks,
signatures — and nothing in this repo catches them. Email addresses and IPs are
already pseudonymized; a number sitting next to a redacted email leaves the
machine verbatim today.

## What Changes

- New always-on `phone` detector that pseudonymizes phone numbers with stable,
  reversible fakes (responses, including SSE streams, are unredacted before
  reaching the user — same path as IP/email/VLESS).
- Covered shapes:
  - international / E.164 with explicit `+` country code, with or without
    separators: `+7 999 123-45-67`, `+1 (555) 123-4567`, `+442071234567`
  - Russian national trunk form: `8 (999) 123-45-67`, `89991234567`
  - grouped 10-digit NANP form with separators: `(555) 123-4567`, `555-123-4567`
- New `replace_engine` value `phone`, usable from user config rules too. Fakes
  come from `go-faker`'s `E164PhoneNumber()` (`+` plus 12 digits), long enough
  that reverse substitution cannot corrupt unrelated response text.

Non-goals (deliberate, false-positive risk outweighs coverage):

- Bare unseparated 10-digit runs (`9991234567`) — collides with Unix epoch
  seconds, order ids and account numbers.
- Dot-separated forms (`555.123.4567`) — collides with IP literals, version
  strings and decimal numbers; the IP detector owns dotted digit runs.
- Extensions (`x123`, `ext. 4`) — left in place next to the fake.

## Capabilities

### New Capabilities
- `phone-number-redaction`: detection, pseudonymization and reversal of phone
  numbers in requests and responses.

### Modified Capabilities
<!-- none: openspec/specs/ is empty, no existing spec's requirements change -->

## Impact

- `pkg/redactor/detectors/phone.go` (new): rule set + constructor, built on the
  existing `RegexDetector` and `SecretGroup` support.
- `pkg/redactor/detectors/replace_engine.go`: `phone` engine.
- `pkg/redactor/redactor.go`: register the detector in `New`.
- `README.md`: Anonymization Examples entry.
- No new dependencies (`go-faker` already provides `E164PhoneNumber`).
- Detection stats/audit log gain a `phone` detector type.

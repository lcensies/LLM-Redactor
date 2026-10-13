## ADDED Requirements

### Requirement: Phone numbers are pseudonymized

The redactor SHALL replace phone numbers in outbound content with stable fake
numbers, by default, with no configuration required. Covered shapes are
international numbers with an explicit `+` country code, the Russian national
trunk form (leading `8`, 11 digits), and grouped 10-digit numbers whose groups
are separated by spaces, hyphens or parentheses.

#### Scenario: International number with separators
- **WHEN** a request body contains `+7 999 123-45-67`
- **THEN** the number is replaced by a fake phone number
- **AND** the surrounding text is unchanged

#### Scenario: Russian national form
- **WHEN** content contains `8 (999) 123-45-67` or `89991234567`
- **THEN** each is replaced by a fake phone number

#### Scenario: Grouped 10-digit number
- **WHEN** content contains `(555) 123-4567` or `555-123-4567`
- **THEN** the number is replaced by a fake phone number

#### Scenario: Bare digit runs are left alone
- **WHEN** content contains `9991234567`, a Unix timestamp `1760000000`, or an
  order id `100200300400`
- **THEN** the value is left unchanged

#### Scenario: Dotted and versioned digit runs are left alone
- **WHEN** content contains `192.168.1.10`, `10.0.0.1`, `v1.2.3` or `555.123.4567`
- **THEN** the phone detector changes nothing (dotted digit runs belong to the IP detector)

#### Scenario: Digits inside tokens are left alone
- **WHEN** a base64 or random token contains a `+` followed by digits, e.g. `aGVsbG8+1234567890abc`
- **THEN** the token is not rewritten by the phone detector

### Requirement: Phone pseudonyms are stable and reversible

Each real number SHALL map to exactly one fake for the lifetime of the process,
and that fake SHALL map back to the real number. Responses, including streamed
responses, SHALL be unredacted so the user sees the original number.

#### Scenario: Same number twice
- **WHEN** the same number appears in two different requests in one session
- **THEN** both are replaced by the identical fake number

#### Scenario: Model echoes a redacted number back
- **WHEN** a response body or SSE stream contains the fake number
- **THEN** the original number is restored before the response reaches the client

#### Scenario: Formatting is not preserved
- **WHEN** a real number written as `8 (999) 123-45-67` is redacted
- **THEN** the fake is a single `+`-prefixed E.164-shaped token, not the original grouping
- **AND** restoring the fake yields the original string `8 (999) 123-45-67` exactly

### Requirement: Fakes are long enough for safe reverse substitution

Generated fake numbers SHALL be at least 13 characters long (`+` plus 12
digits) regardless of the real number's length, so that restoring them by
substring replacement cannot corrupt unrelated response text.

#### Scenario: Short national number
- **WHEN** a 10-digit grouped number is redacted
- **THEN** the fake written to the outbound request is a `+`-prefixed 12-digit number

#### Scenario: Fake is not re-redacted into a second fake
- **WHEN** a fake number produced by this detector is present in content that the detector processes
- **THEN** no phone rule rewrites it, so the fake→real mapping stays intact

### Requirement: `phone` is available as a replace_engine

User-configured regex rules SHALL be able to set `replace_engine = "phone"` and
receive the same stable, reversible fake phone numbers.

#### Scenario: Config rule with the phone engine
- **WHEN** a config rule matches a value and declares `replace_engine = "phone"`
- **THEN** the value is replaced by a fake phone number and restored in responses

### Requirement: Detections are audited

Every phone number replacement SHALL emit a detection event with a `phone`
detector type and the rule id that matched, using the existing masked-content
audit path.

#### Scenario: Audit entry for a redacted number
- **WHEN** a phone number is redacted
- **THEN** `detections.jsonl` gains an entry with `detector_type: "phone"`, the rule id, and the masked value
- **AND** the summary counts it under the `phone` detector

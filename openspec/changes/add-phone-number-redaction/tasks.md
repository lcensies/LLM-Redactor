## 1. Pseudonymizer engine

- [x] 1.1 Add a `phone` case to `ReplaceEnginePseudonymizer.GetOrCreate` using `faker.E164PhoneNumber()`, and list it in the type comment
- [x] 1.2 `replace_engine_test.go`: a `phone`-engine rule produces a `+`-prefixed fake, stable across calls, restorable

## 2. Detector

- [x] 2.1 `pkg/redactor/detectors/phone.go`: rules for the international `+` form, the Russian national trunk form and the grouped 10-digit form, built with `RegexDetector` + `SecretGroup` where a prefix guard is needed
- [x] 2.2 `NewPhoneDetector()` with `typeName = "phone"` so detections are counted separately
- [x] 2.3 Register it in `redactor.New`'s detector list after the email detector

## 3. Tests

- [x] 3.1 `phone_test.go`: positive cases per spec (international with/without separators, `8 (999) 123-45-67`, `89991234567`, `(555) 123-4567`, `555-123-4567`)
- [x] 3.2 `phone_test.go`: negative cases — bare `9991234567`, epoch `1760000000`, order id `100200300400`, `192.168.1.10`, `v1.2.3`, `555.123.4567`, base64-ish `aGVsbG8+1234567890abc`
- [x] 3.3 `phone_test.go`: round-trip (redact → unredact restores the original string verbatim), stability (same number → same fake), and that a fake re-processed by `Redact` is not rewritten
- [x] 3.4 `redactor_test.go`: end-to-end `RedactRequest` + `UnredactResponse` on a body with a phone number

## 4. Docs

- [x] 4.1 Add a "Phone numbers" entry to the Anonymization Examples section of `README.md` and the `phone` engine to the `replace_engine` list

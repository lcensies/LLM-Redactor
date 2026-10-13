package detectors

import "regexp"

// Phone numbers are direct personal data and the most common identifier pasted
// into LLM chats next to the emails the email detector already handles — in
// logs, CRM rows, tickets and signatures. Nothing else in this package catches
// them: a digit run is not a Gitleaks pattern and carries no entropy.
//
// Every rule requires either a leading "+" or explicit group separators.
// Separators never include "." so dotted digit runs (IP literals, versions,
// decimals) stay with the IP detector, and bare unseparated runs are left
// alone because they collide with epoch timestamps, order ids and account
// numbers.
var phoneRules = []RegexRule{
	// International. Go's regexp has no lookbehind, so the "not inside a
	// token" guard is a real capture group and SecretGroup picks the number:
	// "aGVsbG8+1234567890" must not match. Digits are counted one at a time
	// (separator-then-digit) so a run of spaces cannot pad the length.
	phoneRule("phone-intl", "International phone number",
		`(^|[^\w+.])(\+[1-9]\d{0,2}(?:[\s\-()]{0,2}\d){6,13}\b)`, 2),
	// Russian trunk form: 8 followed by 10 digits, optionally grouped.
	phoneRule("phone-ru", "Russian national phone number",
		`\b(8[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2})\b`, 1),
	// Grouped 10-digit (NANP) form. The \b sits inside the second branch: a
	// boundary cannot hold before the "(" of "(555) 123-4567".
	phoneRule("phone-grouped", "Grouped phone number",
		`((?:\(\d{3}\)[\s\-]?|\b\d{3}[\s\-])\d{3}[\s\-]?\d{4})\b`, 1),
}

func phoneRule(id, desc, pattern string, group int) RegexRule {
	return RegexRule{
		ID:            id,
		Description:   desc,
		Regex:         regexp.MustCompile(pattern),
		ReplaceEngine: "phone",
		SecretGroup:   group,
	}
}

// NewPhoneDetector returns a RegexDetector over the built-in phone rules. It
// reports its own type so its detections are counted separately from
// config-loaded Gitleaks rules in the audit log and summary.
func NewPhoneDetector() *RegexDetector {
	d := NewRegexDetector(phoneRules)
	d.typeName = "phone"
	return d
}

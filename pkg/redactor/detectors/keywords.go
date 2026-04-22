package detectors

import "strings"

// ContentMatchesRuleKeywords mirrors gitleaks' pre-regex behavior: if a rule
// lists keywords, at least one must appear in the content (case-insensitive
// substring). Rules with no keywords always apply.
func ContentMatchesRuleKeywords(content string, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	lower := strings.ToLower(content)
	for _, k := range keywords {
		if k == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(k)) {
			return true
		}
	}
	return false
}

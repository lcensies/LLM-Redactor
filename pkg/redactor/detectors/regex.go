package detectors

import (
	"context"
	"regexp"
	"sort"
	"strings"
)

type RegexRule struct {
	ID            string
	Description   string
	Regex         *regexp.Regexp
	ReplaceEngine string
	Keywords      []string
	// SecretGroup mirrors gitleaks' secretGroup: when > 0 only that capture
	// group is replaced and the rest of the match is preserved. 0 (the
	// default) replaces the whole match.
	SecretGroup int
}

type RegexDetector struct {
	rules          []RegexRule
	pseudonymizers map[string]*ReplaceEnginePseudonymizer // keyed by replace_engine (e.g. "company")
	typeName       string                                 // empty means "regex"
}

func NewRegexDetector(rules []RegexRule) *RegexDetector {
	// One pseudonymizer per replace_engine for the detector lifetime (session):
	// the same real string always maps to the same fake across all rules using
	// that engine, and Unredact sees a single fake→real table per engine.
	pseudonymizers := make(map[string]*ReplaceEnginePseudonymizer)
	for _, rule := range rules {
		if rule.ReplaceEngine == "" {
			continue
		}
		if _, exists := pseudonymizers[rule.ReplaceEngine]; !exists {
			pseudonymizers[rule.ReplaceEngine] = NewReplaceEnginePseudonymizer(rule.ReplaceEngine)
		}
	}
	return &RegexDetector{rules: rules, pseudonymizers: pseudonymizers}
}

func (d *RegexDetector) Type() string {
	if d.typeName != "" {
		return d.typeName
	}
	return "regex"
}

func (d *RegexDetector) Redact(ctx context.Context, content string, callback RedactionCallback) string {
	for _, rule := range d.rules {
		rule := rule // capture for closure
		if !ContentMatchesRuleKeywords(content, rule.Keywords) {
			continue
		}
		if rule.SecretGroup > 0 {
			content = d.redactGroup(content, rule, callback)
			continue
		}
		if rule.ReplaceEngine != "" {
			ps := d.pseudonymizers[rule.ReplaceEngine]
			content = rule.Regex.ReplaceAllStringFunc(content, func(match string) string {
				if len(match) == 0 {
					return match
				}
				fake := ps.GetOrCreate(match)
				callback(match, rule.ID, rule.Description)
				return fake
			})
		} else {
			content = rule.Regex.ReplaceAllStringFunc(content, func(match string) string {
				if len(match) == 0 {
					return match
				}
				return callback(match, rule.ID, rule.Description)
			})
		}
	}
	return content
}

// redactGroup replaces only rule.SecretGroup of every match, keeping the rest
// of the match (typically the anchoring key, e.g. `"short_id": "`) intact.
// Matches where the group is out of range or did not participate are left
// untouched and record no detection.
func (d *RegexDetector) redactGroup(content string, rule RegexRule, callback RedactionCallback) string {
	matches := rule.Regex.FindAllStringSubmatchIndex(content, -1)
	if len(matches) == 0 {
		return content
	}
	ps := d.pseudonymizers[rule.ReplaceEngine]
	var b strings.Builder
	last := 0
	for _, m := range matches {
		lo, hi := 2*rule.SecretGroup, 2*rule.SecretGroup+1
		if hi >= len(m) || m[lo] < 0 || m[hi] <= m[lo] {
			continue
		}
		match := content[m[lo]:m[hi]]
		var replacement string
		if ps != nil {
			replacement = ps.GetOrCreate(match)
			callback(match, rule.ID, rule.Description)
		} else {
			replacement = callback(match, rule.ID, rule.Description)
		}
		b.WriteString(content[last:m[lo]])
		b.WriteString(replacement)
		last = m[hi]
	}
	b.WriteString(content[last:])
	return b.String()
}

// Unredact restores pseudonymized values produced by replace_engine rules.
func (d *RegexDetector) Unredact(content string) string {
	if len(d.pseudonymizers) == 0 {
		return content
	}
	engines := make([]string, 0, len(d.pseudonymizers))
	for e := range d.pseudonymizers {
		engines = append(engines, e)
	}
	sort.Strings(engines)
	for _, e := range engines {
		ps := d.pseudonymizers[e]
		ps.mu.RLock()
		pairs := make([]struct {
			fake, real string
		}, 0, len(ps.fakeToReal))
		for fake, real := range ps.fakeToReal {
			pairs = append(pairs, struct {
				fake, real string
			}{fake, real})
		}
		ps.mu.RUnlock()
		// Longest fake first so a shorter token cannot truncate a longer fake
		// (e.g. paths or URLs where one pseudonym is a substring of another).
		sort.Slice(pairs, func(i, j int) bool {
			return len(pairs[i].fake) > len(pairs[j].fake)
		})
		for _, p := range pairs {
			content = strings.ReplaceAll(content, p.fake, p.real)
		}
	}
	return content
}

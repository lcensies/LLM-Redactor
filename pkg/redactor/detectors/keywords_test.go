package detectors

import (
	"context"
	"regexp"
	"testing"
)

func TestContentMatchesRuleKeywords(t *testing.T) {
	t.Parallel()
	if !ContentMatchesRuleKeywords("hello", nil) {
		t.Fatal("nil keywords should match")
	}
	if !ContentMatchesRuleKeywords("hello", []string{}) {
		t.Fatal("empty keywords should match")
	}
	if ContentMatchesRuleKeywords("nix flake prefetch", []string{"sourcegraph"}) {
		t.Fatal("should not match without keyword")
	}
	if !ContentMatchesRuleKeywords("use Sourcegraph please", []string{"sourcegraph"}) {
		t.Fatal("should match case-insensitively")
	}
	if !ContentMatchesRuleKeywords("prefix sgp_ token", []string{"sgp_"}) {
		t.Fatal("should match sgp_ prefix keyword")
	}
}

func TestRegexDetectorSkipsRuleWhenKeywordMissing(t *testing.T) {
	t.Parallel()
	r := RegexRule{
		ID:          "hex40",
		Description: "test",
		Regex:       regexp.MustCompile(`(?i)\b[a-f0-9]{40}\b`),
		Keywords:    []string{"sourcegraph"},
	}
	d := NewRegexDetector([]RegexRule{r})
	s := "hash a87aaeeb478bc30b14a4abab7dedc809b7eaf7ef here"
	out := d.Redact(context.Background(), s, nopCallback)
	if out != s {
		t.Fatalf("expected no redaction without keyword, got %q", out)
	}
	out = d.Redact(context.Background(), "sourcegraph "+s, nopCallback)
	if out == "sourcegraph "+s {
		t.Fatal("expected redaction when keyword present")
	}
}

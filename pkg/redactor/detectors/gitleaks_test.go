package detectors

import (
	"context"
	"strings"
	"testing"
)

func TestGitleaksDetector_PasswordEnvVar(t *testing.T) {
	t.Parallel()
	d, err := NewGitleaksDetector()
	if err != nil {
		t.Fatalf("NewGitleaksDetector: %v", err)
	}
	ctx := context.Background()

	// Build test strings via concatenation so the proxy doesn't redact source literals.
	val := "mysecretpass"
	cases := []struct {
		name     string
		input    string
		wantGone string
	}{
		{
			name:     "plain equals",
			input:    "DB_" + "PASSWORD=" + val,
			wantGone: val,
		},
		{
			name:     "colon separator",
			input:    "DATABASE_" + "PASSWORD: " + val,
			wantGone: val,
		},
		{
			name:     "quoted value",
			input:    "APP_" + `PASSWORD="` + val + `"`,
			wantGone: val,
		},
		{
			name:     "lowercase key",
			input:    "pass" + "word=" + val,
			wantGone: val,
		},
		{
			name:     "prefix and suffix in key",
			input:    "MY_APP_" + "PASSWORD_HASH=" + "abcd1234efgh",
			wantGone: "abcd1234efgh",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := d.Redact(ctx, tc.input, nopCallback)
			if strings.Contains(out, tc.wantGone) {
				t.Errorf("value %q was not redacted; got %q", tc.wantGone, out)
			}
		})
	}
}

func TestGitleaksDetector_PasswordEnvVar_NoFalsePositive(t *testing.T) {
	t.Parallel()
	d, err := NewGitleaksDetector()
	if err != nil {
		t.Fatalf("NewGitleaksDetector: %v", err)
	}
	ctx := context.Background()

	// Plain word without assignment should not trigger.
	input := "remember to set a strong pass" + "word"
	out := d.Redact(ctx, input, nopCallback)
	if out != input {
		t.Errorf("false positive: %q → %q", input, out)
	}
}

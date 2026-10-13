package detectors

import (
	"context"
	"regexp"
	"strings"
	"testing"
)

var fakePhoneRe = regexp.MustCompile(`\+\d{10,15}`)

func TestPhoneDetectorRedactsNumbers(t *testing.T) {
	cases := []string{
		"+7 999 123-45-67",
		"+79991234567",
		"+1 (555) 123-4567",
		"+442071234567",
		"8 (999) 123-45-67",
		"89991234567",
		"8-999-123-45-67",
		"(555) 123-4567",
		"555-123-4567",
		"555 123 4567",
	}
	for _, number := range cases {
		d := NewPhoneDetector()
		in := "call me at " + number + " tomorrow"
		out := d.Redact(context.Background(), in, nopCallback)
		if strings.Contains(out, number) {
			t.Errorf("%q: number still present: %q", number, out)
		}
		if !fakePhoneRe.MatchString(out) {
			t.Errorf("%q: no fake phone in output: %q", number, out)
		}
		if !strings.HasPrefix(out, "call me at ") || !strings.HasSuffix(out, " tomorrow") {
			t.Errorf("%q: surrounding text damaged: %q", number, out)
		}
	}
}

func TestPhoneDetectorLeavesNonPhonesAlone(t *testing.T) {
	cases := []string{
		"order 9991234567 shipped",
		"ts=1760000000 done",
		"order id 100200300400",
		"host 192.168.1.10 up",
		"peer 10.0.0.1 up",
		"release v1.2.3 built",
		"fax 555.123.4567 unused",
		"token aGVsbG8+1234567890abc here",
		"sum is 2+1234567890 exactly",
		"uuid 12345678-1234-5678-9012-345678901234",
		"ratio 1.5 and 0.25",
	}
	for _, in := range cases {
		d := NewPhoneDetector()
		if out := d.Redact(context.Background(), in, nopCallback); out != in {
			t.Errorf("%q was rewritten to %q", in, out)
		}
	}
}

func TestPhoneDetectorRoundTrip(t *testing.T) {
	d := NewPhoneDetector()
	in := "primary 8 (999) 123-45-67, backup +1 (555) 123-4567"
	out := d.Redact(context.Background(), in, nopCallback)
	if out == in {
		t.Fatalf("nothing redacted: %q", out)
	}
	if got := d.Unredact(out); got != in {
		t.Errorf("round trip got %q, want %q", got, in)
	}
}

func TestPhoneDetectorStableFake(t *testing.T) {
	d := NewPhoneDetector()
	first := d.Redact(context.Background(), "+79991234567", nopCallback)
	second := d.Redact(context.Background(), "+79991234567", nopCallback)
	if first != second {
		t.Errorf("unstable fake: %q then %q", first, second)
	}
}

// A fake fed back through Redact must survive unchanged, or the fake→real
// mapping is lost when the model echoes a redacted number back.
func TestPhoneDetectorDoesNotRedactItsOwnFake(t *testing.T) {
	d := NewPhoneDetector()
	fake := d.Redact(context.Background(), "+79991234567", nopCallback)
	if again := d.Redact(context.Background(), fake, nopCallback); again != fake {
		t.Errorf("fake %q was re-redacted to %q", fake, again)
	}
	if got := d.Unredact(fake); got != "+79991234567" {
		t.Errorf("restore got %q, want %q", got, "+79991234567")
	}
}

func TestPhoneDetectorType(t *testing.T) {
	if got := NewPhoneDetector().Type(); got != "phone" {
		t.Errorf("Type() = %q, want %q", got, "phone")
	}
}

func TestReplaceEnginePhoneShape(t *testing.T) {
	p := NewReplaceEnginePseudonymizer("phone")
	fake := p.GetOrCreate("+79991234567")
	if !fakePhoneRe.MatchString(fake) {
		t.Errorf("phone engine returned %q, want a +-prefixed number", fake)
	}
	if real, ok := p.Restore(fake); !ok || real != "+79991234567" {
		t.Errorf("Restore(%q) = (%q, %v)", fake, real, ok)
	}
}

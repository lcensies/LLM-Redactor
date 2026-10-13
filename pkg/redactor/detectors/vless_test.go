package detectors

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

const (
	realUUID    = "3f1c9e2a-11b4-4c8d-9f77-0a1b2c3d4e5f"
	realKey     = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" // 43 chars, base64url of 32 bytes
	realShortID = "0123abcd"
	realSNI     = "www.microsoft.com"
	realHost    = "vpn.example.org"
)

func redactVLESS(t *testing.T, in string) (*RegexDetector, string) {
	t.Helper()
	d := NewVLESSDetector()
	return d, d.Redact(context.Background(), in, nopCallback)
}

// assertScrubbed fails if any real credential survived in out.
func assertScrubbed(t *testing.T, out string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Errorf("real value %q leaked into output: %s", s, out)
		}
	}
}

func TestVLESSRulesAreWellFormed(t *testing.T) {
	if len(vlessRules) == 0 {
		t.Fatal("no VLESS rules registered")
	}
	for _, r := range vlessRules {
		if r.Regex == nil {
			t.Errorf("%s: nil regex", r.ID)
			continue
		}
		if r.SecretGroup != 1 {
			t.Errorf("%s: SecretGroup = %d, want 1", r.ID, r.SecretGroup)
		}
		if r.Regex.NumSubexp() < 1 {
			t.Errorf("%s: regex has no capture group", r.ID)
		}
		if r.ReplaceEngine == "" {
			t.Errorf("%s: no replace_engine, would be masked instead of pseudonymized", r.ID)
		}
		if len(r.Keywords) == 0 {
			t.Errorf("%s: no keywords, rule runs on every payload", r.ID)
		}
		for _, k := range r.Keywords {
			if !ContentMatchesRuleKeywords(k, r.Keywords) {
				t.Errorf("%s: keyword %q does not satisfy its own prefilter", r.ID, k)
			}
		}
	}
}

func TestVLESSDetectorType(t *testing.T) {
	if got := NewVLESSDetector().Type(); got != "vless" {
		t.Fatalf("Type() = %q, want %q", got, "vless")
	}
}

func TestVLESSSingBoxJSON(t *testing.T) {
	in := `{"outbounds":[{"type":"vless","server":"` + realHost + `","server_port":443,` +
		`"uuid":"` + realUUID + `","flow":"xtls-rprx-vision","tls":{"enabled":true,` +
		`"server_name":"` + realSNI + `","reality":{"enabled":true,` +
		`"public_key":"` + realKey + `","short_id":"` + realShortID + `"}}}]}`

	_, out := redactVLESS(t, in)
	assertScrubbed(t, out, realUUID, realKey, realShortID, realSNI)

	for _, key := range []string{`"uuid":"`, `"public_key":"`, `"short_id":"`, `"server_name":"`} {
		if !strings.Contains(out, key) {
			t.Errorf("key %s was destroyed: %s", key, out)
		}
	}
	var v interface{}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("output is no longer valid JSON: %v\n%s", err, out)
	}
}

func TestVLESSXrayCamelCaseJSON(t *testing.T) {
	in := `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"` + realHost + `",` +
		`"port":443,"users":[{"id":"` + realUUID + `","encryption":"none"}]}]},` +
		`"streamSettings":{"realitySettings":{"serverName":"` + realSNI + `",` +
		`"publicKey":"` + realKey + `","shortId":"` + realShortID + `"}}}]}`

	_, out := redactVLESS(t, in)
	assertScrubbed(t, out, realUUID, realKey, realShortID, realSNI)

	var v interface{}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("output is no longer valid JSON: %v\n%s", err, out)
	}
}

func TestVLESSShareLinkURI(t *testing.T) {
	in := "vless://" + realUUID + "@" + realHost + ":443?security=reality&pbk=" + realKey +
		"&sid=" + realShortID + "&sni=" + realSNI + "&type=tcp#MyNode"

	_, out := redactVLESS(t, in)
	assertScrubbed(t, out, realUUID, realKey, realShortID, realSNI, realHost)

	for _, keep := range []string{"vless://", ":443", "security=reality", "type=tcp", "#MyNode"} {
		if !strings.Contains(out, keep) {
			t.Errorf("expected %q preserved, got: %s", keep, out)
		}
	}
}

func TestVLESSNegativeCases(t *testing.T) {
	cases := []string{
		`{"id":"msg_01ABCdefGHIjklMNOpqr"}`,
		`{"id":42}`,
		`{"signature":"` + realKey + `"}`,
		`{"type":"vless","flow":"xtls-rprx-vision","port":443}`,
		`{"user_id":"` + realUUID + `-suffix"}`,
	}
	for _, in := range cases {
		if _, out := redactVLESS(t, in); out != in {
			t.Errorf("expected no redaction\n in: %s\nout: %s", in, out)
		}
	}
}

func TestVLESSStableAcrossCallsAndForms(t *testing.T) {
	d := NewVLESSDetector()
	ctx := context.Background()
	a := d.Redact(ctx, `{"uuid":"`+realUUID+`"}`, nopCallback)
	b := d.Redact(ctx, `{"uuid":"`+realUUID+`"}`, nopCallback)
	if a != b {
		t.Fatalf("unstable mapping: %q then %q", a, b)
	}
	// The URI form must reuse the same fake as the JSON form: same engine,
	// same session pseudonymizer.
	uri := d.Redact(ctx, "vless://"+realUUID+"@"+realHost+":443", nopCallback)
	fake := strings.TrimSuffix(strings.TrimPrefix(a, `{"uuid":"`), `"}`)
	if !strings.Contains(uri, fake) {
		t.Fatalf("URI form used a different fake: %q vs %q", uri, fake)
	}
}

func TestVLESSRoundTrip(t *testing.T) {
	for _, in := range []string{
		`{"uuid":"` + realUUID + `","public_key":"` + realKey + `","short_id":"` + realShortID + `","server_name":"` + realSNI + `"}`,
		"vless://" + realUUID + "@" + realHost + ":443?pbk=" + realKey + "&sid=" + realShortID + "&sni=" + realSNI + "#MyNode",
	} {
		d, out := redactVLESS(t, in)
		if restored := d.Unredact(out); restored != in {
			t.Errorf("round-trip failed\nwant: %s\n got: %s", in, restored)
		}
	}
}

// A two-character short_id must still be pseudonymized with a 16-char fake:
// Unredact restores by substring replacement over whole response bodies.
func TestVLESSShortIDFakeIsLongEnoughToRestoreSafely(t *testing.T) {
	d := NewVLESSDetector()
	out := d.Redact(context.Background(), `{"short_id":"ab"}`, nopCallback)
	fake := strings.TrimSuffix(strings.TrimPrefix(out, `{"short_id":"`), `"}`)
	if len(fake) != 16 {
		t.Fatalf("fake short_id = %q (len %d), want 16 chars", fake, len(fake))
	}
	if got := d.Unredact(`the word "grab" and ` + fake); got != `the word "grab" and ab` {
		t.Fatalf("unredact corrupted surrounding text: %q", got)
	}
}

// IP literals belong to the IP detector, which runs first. Pseudonymizing its
// fake IP a second time here would break the restore chain.
func TestVLESSDoesNotTouchIPLiteralHosts(t *testing.T) {
	in := "vless://" + realUUID + "@203.0.113.7:443?sni=198.51.100.9"
	_, out := redactVLESS(t, in)
	for _, ip := range []string{"203.0.113.7", "198.51.100.9"} {
		if !strings.Contains(out, ip) {
			t.Errorf("IP %s was rewritten by the VLESS detector: %s", ip, out)
		}
	}
	assertScrubbed(t, out, realUUID)
}

package detectors

import "regexp"

// VLESS/REALITY proxy configs (Xray, sing-box, v2rayN) get pasted into LLM
// chats for debugging. They carry values that identify and grant access to a
// private server: the client UUID, the REALITY public key and short id, and the
// server's SNI/host. Nothing else in this package catches them — a UUID is not
// a Gitleaks pattern and a 43-char base64url key looks like any other token.
//
// Every rule below anchors on a key or query parameter and uses SecretGroup so
// only the value is replaced. Bare patterns (a 2-16 char hex string, say) would
// fire on half the traffic.
const (
	// uuidPattern is a hyphenated UUID. Fakes are UUID-shaped too, so rules
	// that match on a UUID still work after an earlier rule replaced it.
	uuidPattern = `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`
	// hostPattern requires an alphabetic TLD so IP literals do not match: the
	// IP detector runs first and owns those, and pseudonymizing its fake IP a
	// second time would break the restore chain.
	hostPattern = `(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,}`
	// x25519 public key, base64url without padding.
	keyPattern     = `[A-Za-z0-9_-]{43}`
	shortIDPattern = `[0-9a-fA-F]{2,16}`
)

func vlessRule(id, desc, pattern, engine string, keywords ...string) RegexRule {
	return RegexRule{
		ID:            id,
		Description:   desc,
		Regex:         regexp.MustCompile(pattern),
		ReplaceEngine: engine,
		Keywords:      keywords,
		SecretGroup:   1,
	}
}

// vlessRules is ordered: the URI uuid rule runs before the URI host rule, which
// matches on the (fake, still UUID-shaped) uuid preceding the host.
var vlessRules = []RegexRule{
	vlessRule("vless-uuid", "VLESS client UUID",
		`(?i)"(?:uuid|id)"\s*:\s*"(`+uuidPattern+`)"`, "uuid", "uuid", `"id"`),
	vlessRule("vless-public-key", "REALITY public key",
		`(?i)"(?:public_key|publickey|pbk)"\s*:\s*"(`+keyPattern+`)"`, "base64key", "public_key", "publickey", "pbk"),
	vlessRule("vless-short-id", "REALITY short id",
		`(?i)"(?:short_id|shortid|sid)"\s*:\s*"(`+shortIDPattern+`)"`, "hex", "short_id", "shortid", `"sid"`),
	vlessRule("vless-sni", "VLESS server name (SNI)",
		`(?i)"(?:server_name|servername|sni)"\s*:\s*"(`+hostPattern+`)"`, "domain", "server_name", "servername", "sni"),

	vlessRule("vless-uri-uuid", "VLESS URI client UUID",
		`(?i)vless://(`+uuidPattern+`)@`, "uuid", "vless://"),
	vlessRule("vless-uri-host", "VLESS URI server host",
		`(?i)vless://`+uuidPattern+`@(`+hostPattern+`)`, "domain", "vless://"),
	vlessRule("vless-uri-pbk", "VLESS URI REALITY public key",
		`(?i)[?&](?:pbk|publickey)=(`+keyPattern+`)`, "base64key", "pbk", "publickey"),
	vlessRule("vless-uri-sid", "VLESS URI REALITY short id",
		`(?i)[?&](?:sid|shortid)=(`+shortIDPattern+`)`, "hex", "sid=", "shortid="),
	vlessRule("vless-uri-sni", "VLESS URI server name (SNI)",
		`(?i)[?&]sni=(`+hostPattern+`)`, "domain", "sni="),
}

// NewVLESSDetector returns a RegexDetector over the built-in VLESS rules. It
// reports its own type so its detections are counted separately from
// config-loaded Gitleaks rules in the audit log and summary.
func NewVLESSDetector() *RegexDetector {
	d := NewRegexDetector(vlessRules)
	d.typeName = "vless"
	return d
}

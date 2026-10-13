package detectors

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	mathrand "math/rand"
	"sync"

	"github.com/go-faker/faker/v4"
)

// companySuffixes are common business entity suffixes used to generate
// realistic-looking fake company names.
var companySuffixes = []string{
	"Inc", "Corp", "LLC", "Ltd", "Group", "Solutions",
	"Technologies", "Systems", "Consulting", "Services",
	"Partners", "Associates", "Enterprises", "Holdings",
}

func randomCompanyName() string {
	suffix := companySuffixes[mathrand.Intn(len(companySuffixes))]
	return faker.LastName() + " " + suffix
}

// randomBytes returns n cryptographically random bytes. crypto/rand.Read never
// returns an error on any supported platform; it panics rather than silently
// emitting a predictable "fake" key if that ever changes.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("detectors: crypto/rand unavailable: " + err.Error())
	}
	return b
}

// randomBase64Key returns a 43-character base64url string: the shape of an
// x25519 public key as used by REALITY.
func randomBase64Key() string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(32))
}

// randomHexID returns 16 hex characters. The length is fixed regardless of the
// real value's length: Unredact restores fakes by substring replacement over
// whole response bodies, and a short fake (a 2-character short_id, say) would
// rewrite unrelated text.
func randomHexID() string {
	return hex.EncodeToString(randomBytes(8))
}

func randomPersonName() string {
	return faker.FirstName() + " " + faker.LastName()
}

// ReplaceEnginePseudonymizer provides stable bidirectional mappings for
// replace_engine values: "company", "name", "email", "uuid", "base64key",
// "hex", "domain", and "phone".
type ReplaceEnginePseudonymizer struct {
	mu         sync.RWMutex
	realToFake map[string]string
	fakeToReal map[string]string
	engine     string
}

func NewReplaceEnginePseudonymizer(engine string) *ReplaceEnginePseudonymizer {
	return &ReplaceEnginePseudonymizer{
		realToFake: make(map[string]string),
		fakeToReal: make(map[string]string),
		engine:     engine,
	}
}

func (p *ReplaceEnginePseudonymizer) GetOrCreate(real string) string {
	p.mu.RLock()
	if fake, ok := p.realToFake[real]; ok {
		p.mu.RUnlock()
		return fake
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	if fake, ok := p.realToFake[real]; ok {
		return fake
	}

	// A value that is already one of our fakes maps to itself: re-redacting a
	// fake (the model echoes it back, the user pastes it again) would otherwise
	// chain fake→fake and break the single-pass restore in Unredact.
	if _, isFake := p.fakeToReal[real]; isFake {
		return real
	}

	var fake string
	for {
		switch p.engine {
		case "company":
			fake = randomCompanyName()
		case "name":
			fake = randomPersonName()
		case "email":
			fake = faker.Email()
		case "uuid":
			fake = faker.UUIDHyphenated()
		case "base64key":
			fake = randomBase64Key()
		case "hex":
			fake = randomHexID()
		case "domain":
			fake = faker.DomainName()
		case "phone":
			fake = faker.E164PhoneNumber()
		default:
			fake = randomPersonName()
		}
		if _, exists := p.fakeToReal[fake]; !exists {
			break
		}
	}

	p.realToFake[real] = fake
	p.fakeToReal[fake] = real
	return fake
}

func (p *ReplaceEnginePseudonymizer) Restore(fake string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	real, ok := p.fakeToReal[fake]
	return real, ok
}

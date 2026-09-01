package totp_test

import (
	"strings"
	"testing"
	"time"

	"github.com/alternayte/auth-all/internal/totp"
)

// rfcSecret is the shared secret of the RFC 4226 and RFC 6238 test vectors.
var rfcSecret = []byte("12345678901234567890")

// TestGenerateMatchesRFC6238 checks the SHA-1 vectors of RFC 6238 appendix B.
// The vectors carry eight digits, so the test sets Digits to eight.
func TestGenerateMatchesRFC6238(t *testing.T) {
	p := totp.Params{Digits: 8, Period: 30 * time.Second}
	cases := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, c := range cases {
		got := totp.Generate(rfcSecret, time.Unix(c.unix, 0).UTC(), p)
		if got != c.want {
			t.Errorf("at T=%d the code is %q and the vector is %q", c.unix, got, c.want)
		}
	}
}

// TestGenerateMatchesRFC4226 checks the six-digit HOTP vectors of RFC 4226.
// One time step of the default parameters equals one HOTP counter value.
func TestGenerateMatchesRFC4226(t *testing.T) {
	p := totp.Default()
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	for counter, code := range want {
		at := time.Unix(int64(counter)*30, 0).UTC()
		if got := totp.Generate(rfcSecret, at, p); got != code {
			t.Errorf("at counter %d the code is %q and the vector is %q", counter, got, code)
		}
	}
}

// TestDefaultParams checks the values that every authenticator application
// expects.
func TestDefaultParams(t *testing.T) {
	p := totp.Default()
	if p.Digits != 6 {
		t.Errorf("the digit count is %d", p.Digits)
	}
	if p.Period != 30*time.Second {
		t.Errorf("the period is %s", p.Period)
	}
	if p.Skew != 1 {
		t.Errorf("the skew is %d", p.Skew)
	}
}

// TestValidateAcceptsTheCurrentCode checks the happy path and the returned
// time step.
func TestValidateAcceptsTheCurrentCode(t *testing.T) {
	p := totp.Default()
	at := time.Unix(1111111111, 0).UTC()
	code := totp.Generate(rfcSecret, at, p)

	step, ok := totp.Validate(rfcSecret, code, at, p)
	if !ok {
		t.Fatal("Validate refused the current code")
	}
	if want := int64(1111111111 / 30); step != want {
		t.Fatalf("the step is %d and the expected step is %d", step, want)
	}
}

// TestValidateAcceptsOneStepOfSkew checks that a clock difference of thirty
// seconds in each direction still authenticates.
func TestValidateAcceptsOneStepOfSkew(t *testing.T) {
	p := totp.Default()
	at := time.Unix(1111111111, 0).UTC()

	behind := totp.Generate(rfcSecret, at.Add(-30*time.Second), p)
	step, ok := totp.Validate(rfcSecret, behind, at, p)
	if !ok {
		t.Fatal("Validate refused a code of the previous step")
	}
	if want := int64(1111111111/30) - 1; step != want {
		t.Fatalf("the step of the previous code is %d and the expected step is %d", step, want)
	}

	ahead := totp.Generate(rfcSecret, at.Add(30*time.Second), p)
	step, ok = totp.Validate(rfcSecret, ahead, at, p)
	if !ok {
		t.Fatal("Validate refused a code of the next step")
	}
	if want := int64(1111111111/30) + 1; step != want {
		t.Fatalf("the step of the next code is %d and the expected step is %d", step, want)
	}
}

// TestValidateRefusesAnOldCode checks that the skew window is bounded. A code
// of two steps back must not authenticate.
func TestValidateRefusesAnOldCode(t *testing.T) {
	p := totp.Default()
	at := time.Unix(1111111111, 0).UTC()
	old := totp.Generate(rfcSecret, at.Add(-60*time.Second), p)
	if _, ok := totp.Validate(rfcSecret, old, at, p); ok {
		t.Fatal("Validate accepted a code of two steps back")
	}
}

// TestValidateRefusesAWrongSecret checks that a code of a different secret
// never authenticates.
func TestValidateRefusesAWrongSecret(t *testing.T) {
	p := totp.Default()
	at := time.Unix(1111111111, 0).UTC()
	code := totp.Generate([]byte("09876543210987654321"), at, p)
	if _, ok := totp.Validate(rfcSecret, code, at, p); ok {
		t.Fatal("Validate accepted a code of a different secret")
	}
}

// TestValidateRefusesAMalformedCode checks the input guard. A short code, a
// long code, an empty code, and a code with a letter all fail.
func TestValidateRefusesAMalformedCode(t *testing.T) {
	p := totp.Default()
	at := time.Unix(1111111111, 0).UTC()
	valid := totp.Generate(rfcSecret, at, p)
	cases := []string{
		"",
		"12345",
		"1234567",
		"05047a",
		" " + valid,
		valid + " ",
		strings.Repeat("0", 6),
	}
	for _, c := range cases {
		if c == valid {
			continue
		}
		if _, ok := totp.Validate(rfcSecret, c, at, p); ok {
			t.Errorf("Validate accepted the code %q", c)
		}
	}
}

// TestValidateRefusesAnEmptySecret checks that an unset secret authenticates
// nothing.
func TestValidateRefusesAnEmptySecret(t *testing.T) {
	p := totp.Default()
	at := time.Unix(1111111111, 0).UTC()
	if _, ok := totp.Validate(nil, "000000", at, p); ok {
		t.Fatal("Validate accepted a code for an empty secret")
	}
}

// TestNewSecretReturnsTwentyRandomBytes checks the length and the randomness
// of a new secret.
func TestNewSecretReturnsTwentyRandomBytes(t *testing.T) {
	first, err := totp.NewSecret()
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	if len(first) != 20 {
		t.Fatalf("the secret is %d bytes", len(first))
	}
	second, err := totp.NewSecret()
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	if string(first) == string(second) {
		t.Fatal("two new secrets are equal")
	}
}

// TestEncodeSecretRoundTrip checks the base32 form that the database keeps and
// the authenticator application reads.
func TestEncodeSecretRoundTrip(t *testing.T) {
	encoded := totp.EncodeSecret(rfcSecret)
	if strings.Contains(encoded, "=") {
		t.Fatalf("the encoded secret carries padding: %q", encoded)
	}
	if encoded != strings.ToUpper(encoded) {
		t.Fatalf("the encoded secret is not upper case: %q", encoded)
	}
	decoded, err := totp.DecodeSecret(encoded)
	if err != nil {
		t.Fatalf("DecodeSecret: %v", err)
	}
	if string(decoded) != string(rfcSecret) {
		t.Fatalf("the round trip returned %q", string(decoded))
	}
}

// TestDecodeSecretRefusesInvalidInput checks the guard of the decoder.
func TestDecodeSecretRefusesInvalidInput(t *testing.T) {
	for _, c := range []string{"", "1", "!!!!!!!!"} {
		if _, err := totp.DecodeSecret(c); err == nil {
			t.Errorf("DecodeSecret accepted %q", c)
		}
	}
}

// TestURICarriesTheEnrolmentParameters checks the otpauth URI that the
// enrolment response returns.
func TestURICarriesTheEnrolmentParameters(t *testing.T) {
	uri := totp.URI(rfcSecret, "Example App", "alice@example.com", totp.Default())
	for _, want := range []string{
		"otpauth://totp/",
		"secret=" + totp.EncodeSecret(rfcSecret),
		"algorithm=SHA1",
		"digits=6",
		"period=30",
		"issuer=Example+App",
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("the URI %q does not carry %q", uri, want)
		}
	}
	// The label names the issuer and the account, so an application that holds
	// two accounts of one person shows them apart.
	if !strings.Contains(uri, "Example%20App:alice@example.com") {
		t.Errorf("the URI carries no issuer and account label: %q", uri)
	}
}

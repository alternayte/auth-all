// Package totp implements the time-based one-time password of RFC 6238 over
// the HMAC one-time password of RFC 4226.
//
// The package supports the single configuration that every authenticator
// application accepts: HMAC-SHA-1, six digits, and a thirty-second step.
//
// SHA-1 is correct here. The HMAC construction does not inherit the collision
// weakness of the bare hash, and an authenticator application that reads a
// different algorithm from the enrolment URI can refuse it.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SecretBytes is the length of a new shared secret. RFC 4226 requires at least
// 128 bits and recommends 160 bits, which is the output length of SHA-1.
const SecretBytes = 20

// ErrInvalidSecret reports a secret that is not valid base32.
var ErrInvalidSecret = errors.New("authall/totp: the secret is not valid base32")

// Params are the parameters of one TOTP configuration.
type Params struct {
	// Digits is the length of a code.
	Digits int
	// Period is the length of one time step.
	Period time.Duration
	// Skew is the number of steps that Validate accepts on each side of the
	// current step. A skew of one covers a clock difference of one period in
	// each direction.
	Skew int
}

// Default returns the parameters that every authenticator application accepts.
func Default() Params {
	return Params{Digits: 6, Period: 30 * time.Second, Skew: 1}
}

// normalize replaces an unset field with its default.
func (p Params) normalize() Params {
	if p.Digits <= 0 {
		p.Digits = 6
	}
	if p.Period <= 0 {
		p.Period = 30 * time.Second
	}
	if p.Skew < 0 {
		p.Skew = 0
	}
	return p
}

// encoding is the base32 alphabet of RFC 4648 with no padding. An
// authenticator application reads an unpadded secret.
var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// EncodeSecret returns the base32 form of a secret. The database keeps this
// form, and the enrolment response shows it to the user.
func EncodeSecret(secret []byte) string {
	return encoding.EncodeToString(secret)
}

// DecodeSecret returns the raw bytes of a base32 secret. It accepts a secret
// with padding and a secret in lower case, because a user can retype one.
func DecodeSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.TrimRight(s, "=")
	if s == "" {
		return nil, ErrInvalidSecret
	}
	raw, err := encoding.DecodeString(s)
	if err != nil {
		return nil, ErrInvalidSecret
	}
	if len(raw) == 0 {
		return nil, ErrInvalidSecret
	}
	return raw, nil
}

// NewSecret returns a new random shared secret.
func NewSecret() ([]byte, error) {
	b := make([]byte, SecretBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("authall/totp: read random bytes: %w", err)
	}
	return b, nil
}

// Step returns the time step counter of an instant.
func Step(t time.Time, p Params) int64 {
	p = p.normalize()
	return t.Unix() / int64(p.Period.Seconds())
}

// Generate returns the code of one time step.
func Generate(secret []byte, t time.Time, p Params) string {
	return code(secret, Step(t, p), p.normalize())
}

// code returns the code of one counter value. This is the HOTP of RFC 4226.
func code(secret []byte, counter int64, p Params) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))

	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// The dynamic truncation of RFC 4226 section 5.3 reads the low four bits
	// of the last byte as the offset of a four-byte window.
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	return fmt.Sprintf("%0*d", p.Digits, int(value)%pow10(p.Digits))
}

// pow10 returns ten to the power of n.
func pow10(n int) int {
	out := 1
	for i := 0; i < n; i++ {
		out *= 10
	}
	return out
}

// Validate reports whether a code authenticates at an instant. It returns the
// time step that matched, which the caller stores to refuse a replay of the
// same code inside its window.
//
// Validate compares in constant time, so a wrong code discloses no digit.
func Validate(secret []byte, input string, t time.Time, p Params) (int64, bool) {
	p = p.normalize()
	if len(secret) == 0 {
		return 0, false
	}
	if !wellFormed(input, p.Digits) {
		return 0, false
	}
	current := Step(t, p)
	// The loop runs over every accepted step and never stops early, so the
	// duration of a refusal does not disclose which step was close.
	var matched int64
	var ok bool
	for offset := -p.Skew; offset <= p.Skew; offset++ {
		step := current + int64(offset)
		if subtle.ConstantTimeCompare([]byte(code(secret, step, p)), []byte(input)) == 1 {
			matched, ok = step, true
		}
	}
	return matched, ok
}

// wellFormed reports whether an input is exactly n decimal digits. A code with
// a space, a letter, or a sign never reaches the HMAC.
func wellFormed(input string, n int) bool {
	if len(input) != n {
		return false
	}
	for i := 0; i < len(input); i++ {
		if input[i] < '0' || input[i] > '9' {
			return false
		}
	}
	return true
}

// URI returns the otpauth URI of an enrolment. An authenticator application
// reads it from a QR code.
//
// The label names the issuer and the account, so a person who holds two
// accounts of one application sees them apart.
func URI(secret []byte, issuer, account string, p Params) string {
	p = p.normalize()
	q := url.Values{}
	q.Set("secret", EncodeSecret(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(p.Digits))
	q.Set("period", strconv.FormatInt(int64(p.Period.Seconds()), 10))

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + issuer + ":" + account,
		RawQuery: q.Encode(),
	}
	return u.String()
}

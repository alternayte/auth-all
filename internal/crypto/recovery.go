package crypto

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// RecoveryCodeGroups and RecoveryCodeGroupSize describe the shape of one code.
// Two groups of five characters read well from paper.
const (
	RecoveryCodeGroups    = 2
	RecoveryCodeGroupSize = 5
)

// recoveryAlphabet holds the characters of a recovery code.
//
// The alphabet omits 0, 1, i, l, and o, because a person copies a code from a
// screen to paper and back. Each character carries log2(31) bits, so a code of
// ten characters carries about 49 bits. A brute-force attack over that space is
// not practical against a rate-limited endpoint.
const recoveryAlphabet = "23456789abcdefghjkmnpqrstuvwxyz"

// NewRecoveryCodes returns n random recovery codes in the form abcde-fghij.
//
// A code is a second factor and a first factor at the same time, so treat the
// returned values like a password reset token. Show them one time and store
// only the hash.
func NewRecoveryCodes(n int) ([]string, error) {
	if n <= 0 {
		return nil, nil
	}
	out := make([]string, 0, n)
	seen := make(map[string]bool, n)
	for len(out) < n {
		code, err := newRecoveryCode()
		if err != nil {
			return nil, err
		}
		// A collision is very unlikely. The check costs nothing and it keeps
		// the promise that a set holds n distinct codes.
		if seen[code] {
			continue
		}
		seen[code] = true
		out = append(out, code)
	}
	return out, nil
}

// newRecoveryCode returns one code.
func newRecoveryCode() (string, error) {
	var b strings.Builder
	max := big.NewInt(int64(len(recoveryAlphabet)))
	for g := 0; g < RecoveryCodeGroups; g++ {
		if g > 0 {
			b.WriteByte('-')
		}
		for i := 0; i < RecoveryCodeGroupSize; i++ {
			// crypto/rand.Int draws without the modulo bias of a plain
			// remainder over a random byte.
			nth, err := rand.Int(rand.Reader, max)
			if err != nil {
				return "", fmt.Errorf("authall/crypto: read random bytes: %w", err)
			}
			b.WriteByte(recoveryAlphabet[nth.Int64()])
		}
	}
	return b.String(), nil
}

// NormalizeRecoveryCode returns the comparable form of a recovery code.
//
// A person retypes a code from paper, so the case, the separator, and the
// spaces vary. The stored hash covers this form, so every variant of one code
// matches.
func NormalizeRecoveryCode(code string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(code) {
		if r == '-' || r == ' ' || r == '\t' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

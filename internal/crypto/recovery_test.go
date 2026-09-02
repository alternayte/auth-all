package crypto_test

import (
	"strings"
	"testing"

	"github.com/alternayte/auth-all/internal/crypto"
)

// TestNewRecoveryCodesReturnsDistinctCodes checks the count and the shape.
func TestNewRecoveryCodesReturnsDistinctCodes(t *testing.T) {
	codes, err := crypto.NewRecoveryCodes(10)
	if err != nil {
		t.Fatalf("NewRecoveryCodes: %v", err)
	}
	if len(codes) != 10 {
		t.Fatalf("the set holds %d codes", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Fatalf("the code %q appears two times", c)
		}
		seen[c] = true
		if !strings.Contains(c, "-") {
			t.Fatalf("the code %q carries no separator", c)
		}
		// The separator splits two groups of five characters, which a person
		// can read from paper.
		parts := strings.Split(c, "-")
		if len(parts) != 2 || len(parts[0]) != 5 || len(parts[1]) != 5 {
			t.Fatalf("the code %q has the wrong shape", c)
		}
	}
}

// TestRecoveryCodesUseAnUnambiguousAlphabet checks that a person cannot
// confuse two characters when they copy a code.
func TestRecoveryCodesUseAnUnambiguousAlphabet(t *testing.T) {
	codes, err := crypto.NewRecoveryCodes(64)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range codes {
		for _, r := range strings.ReplaceAll(c, "-", "") {
			if strings.ContainsRune("01ilo", r) {
				t.Fatalf("the code %q carries the ambiguous character %q", c, r)
			}
			if r >= 'A' && r <= 'Z' {
				t.Fatalf("the code %q is not lower case", c)
			}
		}
	}
}

// TestNewRecoveryCodesAreRandom checks that two sets differ.
func TestNewRecoveryCodesAreRandom(t *testing.T) {
	first, err := crypto.NewRecoveryCodes(10)
	if err != nil {
		t.Fatal(err)
	}
	second, err := crypto.NewRecoveryCodes(10)
	if err != nil {
		t.Fatal(err)
	}
	for i := range first {
		if first[i] == second[i] {
			t.Fatalf("two sets share the code %q at position %d", first[i], i)
		}
	}
}

// TestNormalizeRecoveryCode checks that a retyped code still matches. A person
// reads a code from paper, so the case, the separator, and the spaces vary.
func TestNormalizeRecoveryCode(t *testing.T) {
	codes, err := crypto.NewRecoveryCodes(1)
	if err != nil {
		t.Fatal(err)
	}
	code := codes[0]
	want := crypto.NormalizeRecoveryCode(code)
	if want == "" {
		t.Fatal("the normalized code is empty")
	}
	if strings.Contains(want, "-") {
		t.Fatalf("the normalized code keeps the separator: %q", want)
	}
	variants := []string{
		strings.ToUpper(code),
		strings.ReplaceAll(code, "-", ""),
		" " + code + " ",
		strings.ReplaceAll(code, "-", " "),
		strings.ToUpper(strings.ReplaceAll(code, "-", "")),
	}
	for _, v := range variants {
		if got := crypto.NormalizeRecoveryCode(v); got != want {
			t.Errorf("the variant %q normalized to %q and the code normalized to %q", v, got, want)
		}
	}
}

// TestNormalizeRecoveryCodeRejectsNothing checks that normalization never
// invents a match for an empty input.
func TestNormalizeRecoveryCodeRejectsNothing(t *testing.T) {
	for _, in := range []string{"", "   ", "-", "- -"} {
		if got := crypto.NormalizeRecoveryCode(in); got != "" {
			t.Errorf("the input %q normalized to %q", in, got)
		}
	}
}

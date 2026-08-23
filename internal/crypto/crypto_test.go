package crypto

import (
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	params := DefaultArgon2Params()
	params.Memory = 8 * 1024
	params.Iterations = 1
	encoded, err := HashPassword("a strong password", params)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded, "a strong password") {
		t.Fatalf("the encoded hash carries the password")
	}
	if !strings.HasPrefix(encoded, "$argon2id$") {
		t.Fatalf("unexpected encoding %q", encoded)
	}
	ok, stored, err := VerifyPassword("a strong password", encoded)
	if err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	if stored.Memory != params.Memory || stored.Iterations != params.Iterations {
		t.Fatalf("the parameters are not encoded with the hash: %+v", stored)
	}
	bad, _, err := VerifyPassword("another password", encoded)
	if err != nil || bad {
		t.Fatalf("an invalid password verified")
	}
}

func TestHashIsSaltedPerCall(t *testing.T) {
	params := DefaultArgon2Params()
	params.Memory = 8 * 1024
	params.Iterations = 1
	first, _ := HashPassword("same password", params)
	second, _ := HashPassword("same password", params)
	if first == second {
		t.Fatalf("two hashes of one password are equal, so the salt is reused")
	}
}

func TestLongPasswordIsSupported(t *testing.T) {
	params := DefaultArgon2Params()
	params.Memory = 8 * 1024
	params.Iterations = 1
	long := strings.Repeat("correct horse battery staple ", 100)
	encoded, err := HashPassword(long, params)
	if err != nil {
		t.Fatal(err)
	}
	ok, _, err := VerifyPassword(long, encoded)
	if err != nil || !ok {
		t.Fatalf("a long password does not verify: %v %v", ok, err)
	}
	// A truncated password must not verify.
	if ok, _, _ := VerifyPassword(long[:len(long)-5], encoded); ok {
		t.Fatalf("a truncated password verified")
	}
}

func TestNeedsRehash(t *testing.T) {
	current := DefaultArgon2Params()
	older := current
	older.Iterations = 1
	if !NeedsRehash(older, current) {
		t.Fatalf("changed parameters must require a rehash")
	}
	if NeedsRehash(current, current) {
		t.Fatalf("equal parameters must not require a rehash")
	}
}

func TestInvalidHashIsRejected(t *testing.T) {
	cases := []string{"", "plaintext", "$argon2id$v=19$m=x,t=1,p=1$abc$def", "$bcrypt$v=19$m=1,t=1,p=1$YQ$Yg"}
	for _, c := range cases {
		if _, _, err := VerifyPassword("password", c); err == nil {
			t.Fatalf("the malformed hash %q was accepted", c)
		}
	}
}

func TestTokenGeneration(t *testing.T) {
	first, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	second, _ := NewToken()
	if first == second {
		t.Fatalf("two tokens are equal")
	}
	// 32 random bytes are 256 bits and encode to 43 characters.
	if len(first) < 43 {
		t.Fatalf("the token carries less than 256 bits: %q", first)
	}
	if HashToken(first) == first {
		t.Fatalf("the hash equals the token")
	}
	if len(HashToken(first)) != 64 {
		t.Fatalf("unexpected hash length")
	}
	if HashToken(first) != HashToken(first) {
		t.Fatalf("the hash is not stable")
	}
}

func TestPKCEChallenge(t *testing.T) {
	verifier, err := NewPKCEVerifier()
	if err != nil {
		t.Fatal(err)
	}
	challenge := PKCEChallenge(verifier)
	if challenge == verifier {
		t.Fatalf("the challenge equals the verifier")
	}
	if PKCEChallenge(verifier) != challenge {
		t.Fatalf("the challenge is not stable")
	}
	if PKCEChallenge("other") == challenge {
		t.Fatalf("two verifiers produced one challenge")
	}
}

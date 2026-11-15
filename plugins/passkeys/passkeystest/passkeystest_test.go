package passkeystest

import (
	"encoding/json"
	"testing"
)

// TestTheAuthenticatorRefusesBadOptions pins the errors that a host test sees
// when it passes the wrong value.
func TestTheAuthenticatorRefusesBadOptions(t *testing.T) {
	a := New("example.com", "https://example.com")
	for name, options := range map[string]json.RawMessage{
		"not JSON":     json.RawMessage(`{`),
		"no challenge": json.RawMessage(`{"publicKey":{}}`),
		"bad user":     json.RawMessage(`{"publicKey":{"challenge":"abc","user":{"id":"%%"}}}`),
	} {
		if _, err := a.Register(options); err == nil {
			t.Fatalf("Register accepted %s", name)
		}
	}
	for name, options := range map[string]json.RawMessage{
		"not JSON":      json.RawMessage(`{`),
		"no challenge":  json.RawMessage(`{"publicKey":{}}`),
		"no credential": json.RawMessage(`{"publicKey":{"challenge":"abc"}}`),
	} {
		if _, err := a.SignIn(options); err == nil {
			t.Fatalf("SignIn accepted %s", name)
		}
	}
}

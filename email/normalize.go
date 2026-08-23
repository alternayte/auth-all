package email

import (
	"net/mail"
	"strings"
)

// Normalize returns the canonical form Auth-All uses to look up an address.
// The form trims surrounding space and lowercases the address. Auth-All does
// not apply provider-specific rules such as removing dots, because those rules
// differ per provider and can merge distinct accounts.
func Normalize(address string) string {
	return strings.ToLower(strings.TrimSpace(address))
}

// Valid reports whether the address is a single parsable email address.
func Valid(address string) bool {
	address = strings.TrimSpace(address)
	if address == "" || len(address) > 320 {
		return false
	}
	if strings.ContainsAny(address, " \t\r\n<>,;\"") {
		return false
	}
	addr, err := mail.ParseAddress(address)
	if err != nil {
		return false
	}
	if addr.Address != address {
		return false
	}
	at := strings.LastIndex(address, "@")
	if at <= 0 || at == len(address)-1 {
		return false
	}
	return strings.Contains(address[at+1:], ".")
}

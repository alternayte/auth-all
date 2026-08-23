package email

import "testing"

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"  User@Example.COM ": "user@example.com",
		"user@example.com":    "user@example.com",
		"USER+tag@EXAMPLE.io": "user+tag@example.io",
	}
	for input, want := range cases {
		if got := Normalize(input); got != want {
			t.Fatalf("Normalize(%q) = %q, want %q", input, got, want)
		}
	}
	// The dots of a local part stay, because removing them can merge two
	// distinct accounts at providers that treat them as significant.
	if Normalize("first.last@example.com") == Normalize("firstlast@example.com") {
		t.Fatalf("the normalization removed dots from the local part")
	}
}

func TestValid(t *testing.T) {
	valid := []string{"user@example.com", "first.last+tag@sub.example.co.uk"}
	for _, v := range valid {
		if !Valid(v) {
			t.Fatalf("%q must be valid", v)
		}
	}
	invalid := []string{"", "user", "user@", "@example.com", "user@example", "a b@example.com",
		"User <user@example.com>", "user@example.com, other@example.com", "user@exam ple.com"}
	for _, v := range invalid {
		if Valid(v) {
			t.Fatalf("%q must be invalid", v)
		}
	}
}

// Package email defines the provider-independent email boundary of Auth-All.
// The application owns delivery. Auth-All supplies intent and required data.
package email

import (
	"context"
	"time"
)

// Intent identifies why Auth-All asks the application to send a message.
type Intent string

// Required v1 intents.
const (
	IntentVerifyEmail   Intent = "verify-email"
	IntentResetPassword Intent = "reset-password"
	IntentMagicLink     Intent = "magic-link"
)

// Message is the data Auth-All supplies for one message.
type Message struct {
	// Intent describes the purpose of the message.
	Intent Intent
	// To is the destination email address.
	To string
	// UserID is the target user. It is empty when no user exists yet.
	UserID string
	// Token is the one-time token in plaintext. It exists only here and in the
	// delivered message. Auth-All stores only its hash.
	Token string
	// URL is the ready-to-use action link.
	URL string
	// ExpiresAt is the token expiry.
	ExpiresAt time.Time
	// Data carries additional intent-specific values.
	Data map[string]string
}

// Sender delivers a message. The application can send directly or enqueue the
// work. Auth-All does not require synchronous delivery.
type Sender interface {
	Send(ctx context.Context, message Message) error
}

// SenderFunc adapts a function to the Sender interface.
type SenderFunc func(ctx context.Context, message Message) error

// Send implements Sender.
func (f SenderFunc) Send(ctx context.Context, m Message) error { return f(ctx, m) }

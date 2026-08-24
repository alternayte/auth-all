// Package apierr defines the stable, machine-readable error contract of
// Auth-All. Error codes are part of the public API compatibility surface.
package apierr

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Code is a stable machine-readable error code.
type Code string

// Stable public error codes.
const (
	CodeInvalidRequest       Code = "INVALID_REQUEST"
	CodeInvalidCredentials   Code = "INVALID_CREDENTIALS"
	CodeEmailAlreadyExists   Code = "EMAIL_ALREADY_EXISTS"
	CodeWeakPassword         Code = "WEAK_PASSWORD"
	CodeInvalidToken         Code = "INVALID_TOKEN"
	CodeUnauthorized         Code = "UNAUTHORIZED"
	CodeForbidden            Code = "FORBIDDEN"
	CodeNotFound             Code = "NOT_FOUND"
	CodeMethodNotAllowed     Code = "METHOD_NOT_ALLOWED"
	CodeOriginNotAllowed     Code = "ORIGIN_NOT_ALLOWED"
	CodeEmailNotVerified     Code = "EMAIL_NOT_VERIFIED"
	CodeNoPasswordCredential Code = "NO_PASSWORD_CREDENTIAL"
	CodeAccountAlreadyLinked Code = "ACCOUNT_ALREADY_LINKED"
	CodeAccountNotLinked     Code = "ACCOUNT_NOT_LINKED"
	CodeLastAuthMethod       Code = "LAST_AUTH_METHOD"
	CodeProviderNotFound     Code = "PROVIDER_NOT_FOUND"
	CodeOAuthStateInvalid    Code = "OAUTH_STATE_INVALID"
	CodeOAuthFailed          Code = "OAUTH_FAILED"
	CodeRateLimited          Code = "RATE_LIMITED"
	CodeInternal             Code = "INTERNAL"
)

// Error is a public Auth-All error. It carries a stable code, a safe public
// message, and an optional private cause. The cause is never serialized.
type Error struct {
	Code    Code
	Message string
	Status  int
	cause   error
}

// New returns a public error.
func New(code Code, status int, message string) *Error {
	return &Error{Code: code, Status: status, Message: message}
}

// Error implements the error interface. It returns the public message only.
func (e *Error) Error() string { return string(e.Code) + ": " + e.Message }

// Unwrap returns the private cause.
func (e *Error) Unwrap() error { return e.cause }

// WithCause attaches a private cause. The cause is never exposed publicly.
func (e *Error) WithCause(err error) *Error {
	c := *e
	c.cause = err
	return &c
}

// WithMessage returns a copy with a different public message.
func (e *Error) WithMessage(msg string) *Error {
	c := *e
	c.Message = msg
	return &c
}

// Is supports errors.Is comparison by code.
func (e *Error) Is(target error) bool {
	var t *Error
	if errors.As(target, &t) {
		return t.Code == e.Code
	}
	return false
}

// Predefined errors.
var (
	ErrInvalidRequest       = New(CodeInvalidRequest, http.StatusBadRequest, "The request is invalid.")
	ErrInvalidCredentials   = New(CodeInvalidCredentials, http.StatusUnauthorized, "Invalid email or password.")
	ErrEmailAlreadyExists   = New(CodeEmailAlreadyExists, http.StatusConflict, "An account with this email already exists.")
	ErrWeakPassword         = New(CodeWeakPassword, http.StatusBadRequest, "The password does not meet the password policy.")
	ErrInvalidToken         = New(CodeInvalidToken, http.StatusBadRequest, "The token is invalid or expired.")
	ErrUnauthorized         = New(CodeUnauthorized, http.StatusUnauthorized, "Authentication is required.")
	ErrForbidden            = New(CodeForbidden, http.StatusForbidden, "The operation is not permitted.")
	ErrNotFound             = New(CodeNotFound, http.StatusNotFound, "The resource does not exist.")
	ErrMethodNotAllowed     = New(CodeMethodNotAllowed, http.StatusMethodNotAllowed, "The method is not allowed.")
	ErrOriginNotAllowed     = New(CodeOriginNotAllowed, http.StatusForbidden, "The request origin is not allowed.")
	ErrEmailNotVerified     = New(CodeEmailNotVerified, http.StatusForbidden, "The email address is not verified.")
	ErrNoPasswordCredential = New(CodeNoPasswordCredential, http.StatusBadRequest, "This account has no password.")
	ErrAccountAlreadyLinked = New(CodeAccountAlreadyLinked, http.StatusConflict, "This provider account is already linked to another user.")
	ErrAccountNotLinked     = New(CodeAccountNotLinked, http.StatusNotFound, "This provider account is not linked.")
	ErrLastAuthMethod       = New(CodeLastAuthMethod, http.StatusConflict, "The last remaining authentication method cannot be removed.")
	ErrProviderNotFound     = New(CodeProviderNotFound, http.StatusNotFound, "The provider is not configured.")
	ErrOAuthStateInvalid    = New(CodeOAuthStateInvalid, http.StatusBadRequest, "The OAuth state is invalid or expired.")
	ErrOAuthFailed          = New(CodeOAuthFailed, http.StatusBadRequest, "The provider did not complete authentication.")
	ErrRateLimited          = New(CodeRateLimited, http.StatusTooManyRequests, "Too many requests.")
	ErrInternal             = New(CodeInternal, http.StatusInternalServerError, "An internal error occurred.")
)

// Body is the serialized public error envelope.
type Body struct {
	Error Payload `json:"error"`
}

// Payload is the serialized public error.
type Payload struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
}

// From maps any error to a public error. Unknown errors map to INTERNAL so
// that internal details never reach a client.
func From(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return ErrInternal.WithCause(err)
}

// Write serializes err as the public error envelope.
func Write(w http.ResponseWriter, err error) {
	e := From(err)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(Body{Error: Payload{Code: e.Code, Message: e.Message}})
}

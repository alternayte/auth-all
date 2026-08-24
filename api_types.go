package authall

import (
	"time"

	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/store"
)

// userDTO is the public JSON shape of a user.
type userDTO struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"emailVerified"`
	Name          string    `json:"name"`
	Image         string    `json:"image"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// sessionDTO is the public JSON shape of a session. It never carries a token.
type sessionDTO struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userId"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func toUserDTO(u *store.User) *userDTO {
	if u == nil {
		return nil
	}
	return &userDTO{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerifiedAt != nil,
		Name:          u.DisplayName,
		Image:         u.ImageURL,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}
}

func toSessionDTO(s *store.Session) *sessionDTO {
	if s == nil {
		return nil
	}
	return &sessionDTO{ID: s.ID, UserID: s.UserID, CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt}
}

// sessionEntryDTO is one row of the session list. It never carries a token or
// a token hash.
type sessionEntryDTO struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"createdAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
}

func toSessionEntryDTO(s store.Session) sessionEntryDTO {
	return sessionEntryDTO{
		ID:         s.ID,
		CreatedAt:  s.CreatedAt,
		ExpiresAt:  s.ExpiresAt,
		LastSeenAt: s.LastSeenAt,
	}
}

type sessionListResponse struct {
	Sessions []sessionEntryDTO `json:"sessions"`
}

type revokeAllResponse struct {
	Revoked int `json:"revoked"`
}

type authResponse struct {
	User    *userDTO    `json:"user"`
	Session *sessionDTO `json:"session"`
	// EmailVerificationRequired reports that the account must verify its email
	// address before it can sign in.
	EmailVerificationRequired bool `json:"emailVerificationRequired,omitempty"`
}

type messageResponse struct {
	Message string `json:"message"`
}

type successResponse struct {
	Success bool `json:"success"`
}

type providerEntry struct {
	Provider  string    `json:"provider"`
	AccountID string    `json:"accountId"`
	LinkedAt  time.Time `json:"linkedAt"`
}

type providersResponse struct {
	Providers   []providerEntry `json:"providers"`
	HasPassword bool            `json:"hasPassword"`
}

type linkResponse struct {
	URL string `json:"url"`
}

// registerCoreSchemas adds the reusable component schemas of core.
func registerCoreSchemas(doc *openapi.Document) {
	doc.AddSchema("User", openapi.Object(
		[]string{"id", "email", "emailVerified", "name", "image", "createdAt", "updatedAt"},
		map[string]*openapi.Schema{
			"id":            openapi.String(),
			"email":         openapi.String(),
			"emailVerified": openapi.Bool(),
			"name":          openapi.String(),
			"image":         openapi.String(),
			"createdAt":     {Type: "string", Format: "date-time"},
			"updatedAt":     {Type: "string", Format: "date-time"},
		}))
	doc.AddSchema("Session", openapi.Object(
		[]string{"id", "userId", "createdAt", "expiresAt"},
		map[string]*openapi.Schema{
			"id":        openapi.String(),
			"userId":    openapi.String(),
			"createdAt": {Type: "string", Format: "date-time"},
			"expiresAt": {Type: "string", Format: "date-time"},
		}))
	doc.AddSchema("AuthResponse", openapi.Object(
		[]string{"user", "session"},
		map[string]*openapi.Schema{
			"user":                      {Ref: "#/components/schemas/User", Nullable: true},
			"session":                   {Ref: "#/components/schemas/Session", Nullable: true},
			"emailVerificationRequired": openapi.Bool(),
		}))
	doc.AddSchema("SessionResponse", openapi.Object(
		[]string{"user", "session"},
		map[string]*openapi.Schema{
			"user":    {Ref: "#/components/schemas/User", Nullable: true},
			"session": {Ref: "#/components/schemas/Session", Nullable: true},
		}))
	doc.AddSchema("SessionEntry", openapi.Object(
		[]string{"id", "createdAt", "expiresAt", "lastSeenAt"},
		map[string]*openapi.Schema{
			"id":         openapi.String(),
			"createdAt":  {Type: "string", Format: "date-time"},
			"expiresAt":  {Type: "string", Format: "date-time"},
			"lastSeenAt": {Type: "string", Format: "date-time"},
		}))
	doc.AddSchema("SessionListResponse", openapi.Object(
		[]string{"sessions"},
		map[string]*openapi.Schema{
			"sessions": {Type: "array", Items: openapi.Ref("SessionEntry")},
		}))
	doc.AddSchema("RevokeAllResponse", openapi.Object(
		[]string{"revoked"},
		map[string]*openapi.Schema{"revoked": {Type: "integer"}}))
	doc.AddSchema("MessageResponse", openapi.Object(
		[]string{"message"},
		map[string]*openapi.Schema{"message": openapi.String()}))
	doc.AddSchema("SuccessResponse", openapi.Object(
		[]string{"success"},
		map[string]*openapi.Schema{"success": openapi.Bool()}))
	doc.AddSchema("ErrorResponse", openapi.Object(
		[]string{"error"},
		map[string]*openapi.Schema{
			"error": openapi.Object([]string{"code", "message"}, map[string]*openapi.Schema{
				"code":    openapi.String(),
				"message": openapi.String(),
			}),
		}))
	doc.AddSchema("ProvidersResponse", openapi.Object(
		[]string{"providers", "hasPassword"},
		map[string]*openapi.Schema{
			"providers": {Type: "array", Items: openapi.Object(
				[]string{"provider", "accountId", "linkedAt"},
				map[string]*openapi.Schema{
					"provider":  openapi.String(),
					"accountId": openapi.String(),
					"linkedAt":  {Type: "string", Format: "date-time"},
				})},
			"hasPassword": openapi.Bool(),
		}))
	doc.AddSchema("LinkResponse", openapi.Object(
		[]string{"url"},
		map[string]*openapi.Schema{"url": openapi.String()}))
}

// errorResponses returns the standard error responses of an operation.
func errorResponses(codes ...string) map[string]openapi.Response {
	out := map[string]openapi.Response{}
	for _, c := range codes {
		out[c] = openapi.JSONResponse("Auth-All error", openapi.Ref("ErrorResponse"))
	}
	return out
}

// operation builds an operation with the standard error responses.
func operation(id, summary string, tags []string, body *openapi.RequestBody, okDescription string, okSchema *openapi.Schema, client *openapi.ClientBinding, errorCodes ...string) *openapi.Operation {
	responses := errorResponses(errorCodes...)
	responses["200"] = openapi.JSONResponse(okDescription, okSchema)
	return &openapi.Operation{
		OperationID: id,
		Summary:     summary,
		Tags:        tags,
		RequestBody: body,
		Responses:   responses,
		Client:      client,
	}
}

package apikeys

import (
	"net/http"
	"time"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/store"
)

// keyDTO is the public shape of one key. It never carries the digest and never
// the plaintext.
type keyDTO struct {
	ID         string     `json:"id"`
	UserID     string     `json:"userId"`
	Name       string     `json:"name"`
	Start      string     `json:"start"`
	Role       string     `json:"role"`
	OrgID      *string    `json:"orgId"`
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  *time.Time `json:"expiresAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	RevokedAt  *time.Time `json:"revokedAt"`
}

// listResponse is the body of the list route.
type listResponse struct {
	Keys []keyDTO `json:"keys"`
}

// createRequest is the body of the create route.
type createRequest struct {
	Name string `json:"name"`
	Role string `json:"role"`
	// ExpiresAt ends the key. A nil value means no expiry.
	ExpiresAt *time.Time `json:"expiresAt"`
	// OrgID names the organization of the key. An empty value creates a key of
	// the whole application.
	OrgID string `json:"orgId"`
}

// createResponse carries the plaintext key one time.
type createResponse struct {
	Key       keyDTO `json:"key"`
	Plaintext string `json:"plaintext"`
}

// toDTO returns the public shape of one key.
func toDTO(k *store.APIKey) keyDTO {
	return keyDTO{
		ID: k.ID, UserID: k.UserID, Name: k.Name, Start: k.Start, Role: k.Role,
		OrgID: k.OrgID, CreatedAt: k.CreatedAt, ExpiresAt: k.ExpiresAt,
		LastUsedAt: k.LastUsedAt, RevokedAt: k.RevokedAt,
	}
}

// registerRoutes mounts the key management routes.
func (p *Plugin) registerRoutes(r *plugin.Registry) {
	tag := []string{"api-keys"}
	r.Route(plugin.Route{
		Method: http.MethodGet, Path: "/api-keys", Handler: p.guard(p.handleList),
		Operation: operation("listAPIKeys", "List the API keys", tag, nil,
			openapi.Ref("APIKeyListResponse"), "listKeys"),
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/api-keys", Handler: p.guard(p.handleCreate),
		Operation: operation("createAPIKey", "Create an API key", tag,
			openapi.JSONBody(openapi.Object([]string{"name"}, map[string]*openapi.Schema{
				"name":      openapi.String(),
				"role":      openapi.String(),
				"expiresAt": {Type: "string", Format: "date-time", Nullable: true},
				"orgId":     openapi.String(),
			})),
			openapi.Ref("APIKeyCreateResponse"), "createKey", "400"),
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/api-keys/{id}/revoke", Handler: p.guard(p.handleRevoke),
		Operation: keyOperation("revokeAPIKey", "Revoke an API key", tag, nil,
			openapi.Ref("SuccessResponse"), "revokeKey", "404"),
	})
}

// operation builds one key operation with the standard error responses.
func operation(id, summary string, tag []string, body *openapi.RequestBody,
	okSchema *openapi.Schema, method string, codes ...string) *openapi.Operation {
	return withParameters(id, summary, tag, body, okSchema, method, nil, codes...)
}

// keyOperation builds one operation that names a key in the path.
func keyOperation(id, summary string, tag []string, body *openapi.RequestBody,
	okSchema *openapi.Schema, method string, codes ...string) *openapi.Operation {
	parameters := []openapi.Parameter{
		{Name: "id", In: "path", Required: true, Schema: openapi.String()},
	}
	return withParameters(id, summary, tag, body, okSchema, method, parameters, codes...)
}

// withParameters builds one operation with the standard error responses.
func withParameters(id, summary string, tag []string, body *openapi.RequestBody,
	okSchema *openapi.Schema, method string, parameters []openapi.Parameter,
	codes ...string) *openapi.Operation {
	responses := map[string]openapi.Response{
		"200": openapi.JSONResponse("The operation succeeded", okSchema),
	}
	for _, c := range append([]string{"401", "403"}, codes...) {
		responses[c] = openapi.JSONResponse("Auth-All error", openapi.Ref("ErrorResponse"))
	}
	return &openapi.Operation{
		OperationID: id,
		Summary:     summary,
		Tags:        tag,
		Parameters:  parameters,
		RequestBody: body,
		Responses:   responses,
		Client:      &openapi.ClientBinding{Namespace: "apiKeys", Method: method},
	}
}

// guard requires a session principal. Key management needs a person, so a key
// never manages a key.
func (p *Plugin) guard(fn func(http.ResponseWriter, *http.Request, *plugin.Principal)) http.Handler {
	gate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := p.principals.Current(r.Context())
		if principal == nil {
			p.writeError(w, r, apierr.ErrUnauthorized)
			return
		}
		if principal.Method != "session" {
			p.writeError(w, r, apierr.ErrForbidden.WithMessage("An API key cannot manage an API key."))
			return
		}
		fn(w, r, principal)
	})
	return p.protect(gate)
}

// writeError writes the public error envelope of one request.
func (p *Plugin) writeError(w http.ResponseWriter, r *http.Request, err error) {
	if writer, ok := p.svc.HTTP().(interface {
		WriteErrorFor(http.ResponseWriter, *http.Request, error)
	}); ok {
		writer.WriteErrorFor(w, r, err)
		return
	}
	p.svc.HTTP().WriteError(w, err)
}

// isAdmin reports whether the caller can manage the keys of another user.
func (p *Plugin) isAdmin(principal *plugin.Principal) bool {
	return p.roles.AtLeast(principal.Role, p.adminRole)
}

// handleList serves GET /api-keys. An administrator can name another owner.
func (p *Plugin) handleList(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	owner := principal.User.ID
	if wanted := r.URL.Query().Get("userId"); wanted != "" && wanted != owner {
		if !p.isAdmin(principal) {
			p.writeError(w, r, apierr.ErrForbidden)
			return
		}
		owner = wanted
	}
	keys, err := p.List(r.Context(), owner)
	if err != nil {
		p.writeError(w, r, err)
		return
	}
	out := make([]keyDTO, 0, len(keys))
	for i := range keys {
		out = append(out, toDTO(&keys[i]))
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, listResponse{Keys: out})
}

// handleCreate serves POST /api-keys.
func (p *Plugin) handleCreate(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	var req createRequest
	if err := p.svc.HTTP().DecodeJSON(r, &req); err != nil {
		p.writeError(w, r, err)
		return
	}
	key, plaintext, err := p.Create(r.Context(), principal.User, CreateInput{
		UserID: principal.User.ID, Name: req.Name, Role: req.Role,
		ExpiresAt: req.ExpiresAt, OrgID: req.OrgID,
	})
	if err != nil {
		p.writeError(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusCreated, createResponse{Key: toDTO(key), Plaintext: plaintext})
}

// handleRevoke serves POST /api-keys/{id}/revoke.
func (p *Plugin) handleRevoke(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	if err := p.Revoke(r.Context(), r.PathValue("id"), principal.User, p.isAdmin(principal)); err != nil {
		p.writeError(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

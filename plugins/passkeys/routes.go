package passkeys

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/store"
)

// passkeyDTO is the public shape of one passkey. It carries no key material.
type passkeyDTO struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
}

func toDTO(k *store.Passkey) passkeyDTO {
	return passkeyDTO{ID: k.ID, Name: k.Name, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt}
}

// beginResponse carries the ceremony handle and the options that the browser
// passes to navigator.credentials.create or navigator.credentials.get.
type beginResponse struct {
	Ceremony string `json:"ceremony"`
	Options  any    `json:"options"`
}

// registerFinishRequest is the body of the registration finish route.
type registerFinishRequest struct {
	Ceremony   string          `json:"ceremony"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

// signInFinishRequest is the body of the sign-in finish route.
type signInFinishRequest struct {
	Ceremony   string          `json:"ceremony"`
	Credential json.RawMessage `json:"credential"`
}

// registerSchemas adds the component schemas of the passkey responses.
func registerSchemas(r *plugin.Registry) {
	r.OpenAPISchema("Passkey", openapi.Object(
		[]string{"id", "name", "createdAt", "lastUsedAt"},
		map[string]*openapi.Schema{
			"id":         openapi.String(),
			"name":       openapi.String(),
			"createdAt":  {Type: "string", Format: "date-time"},
			"lastUsedAt": {Type: "string", Format: "date-time", Nullable: true},
		}))
	r.OpenAPISchema("PasskeyResponse", openapi.Object([]string{"passkey"},
		map[string]*openapi.Schema{"passkey": openapi.Ref("Passkey")}))
	r.OpenAPISchema("PasskeyListResponse", openapi.Object([]string{"passkeys"},
		map[string]*openapi.Schema{"passkeys": {Type: "array", Items: openapi.Ref("Passkey")}}))
	r.OpenAPISchema("PasskeyCeremony", openapi.Object([]string{"ceremony", "options"},
		map[string]*openapi.Schema{
			"ceremony": openapi.String(),
			// The WebAuthn options in their JSON form: an object with the
			// member publicKey.
			"options": {Type: "object", AdditionalProperties: &openapi.Schema{}},
		}))
}

// credentialSchema is the JSON form of a PublicKeyCredential, as
// PublicKeyCredential.toJSON returns it.
func credentialSchema() *openapi.Schema {
	return &openapi.Schema{Type: "object", AdditionalProperties: &openapi.Schema{}}
}

// registerRoutes mounts the passkey routes.
func (p *Plugin) registerRoutes(r *plugin.Registry) {
	tag := []string{"passkeys"}
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/passkeys/register/begin", Handler: p.guard(p.handleRegisterBegin),
		Operation: operation("beginPasskeyRegistration", "Start a passkey registration", tag, nil,
			openapi.Ref("PasskeyCeremony"), "registerBegin", "401", "403"),
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/passkeys/register/finish", Handler: p.guard(p.handleRegisterFinish),
		Operation: created(operation("finishPasskeyRegistration", "Finish a passkey registration", tag,
			openapi.JSONBody(openapi.Object([]string{"ceremony", "name", "credential"}, map[string]*openapi.Schema{
				"ceremony":   openapi.String(),
				"name":       openapi.String(),
				"credential": credentialSchema(),
			})),
			openapi.Ref("PasskeyResponse"), "registerFinish", "400", "401", "403")),
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/passkeys/sign-in/begin", Handler: http.HandlerFunc(p.handleSignInBegin),
		Operation: operation("beginPasskeySignIn", "Start a passkey sign-in", tag, nil,
			openapi.Ref("PasskeyCeremony"), "signInBegin", "403", "429"),
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/passkeys/sign-in/finish", Handler: http.HandlerFunc(p.handleSignInFinish),
		Operation: operation("finishPasskeySignIn", "Finish a passkey sign-in", tag,
			openapi.JSONBody(openapi.Object([]string{"ceremony", "credential"}, map[string]*openapi.Schema{
				"ceremony":   openapi.String(),
				"credential": credentialSchema(),
			})),
			openapi.Ref("AuthResponse"), "signInFinish", "400", "403", "429"),
	})
	r.Route(plugin.Route{
		Method: http.MethodGet, Path: "/passkeys", Handler: p.guard(p.handleList),
		Operation: operation("listPasskeys", "List the passkeys", tag, nil,
			openapi.Ref("PasskeyListResponse"), "list", "401", "403"),
	})
	r.Route(plugin.Route{
		Method: http.MethodDelete, Path: "/passkeys/{id}", Handler: p.guard(p.handleDelete),
		Operation: withID(operation("deletePasskey", "Delete a passkey", tag, nil,
			openapi.Ref("SuccessResponse"), "delete", "401", "403", "404")),
	})
}

// operation builds one passkey operation with the error responses.
func operation(id, summary string, tag []string, body *openapi.RequestBody,
	okSchema *openapi.Schema, method string, codes ...string) *openapi.Operation {
	responses := map[string]openapi.Response{
		"200": openapi.JSONResponse("The operation succeeded", okSchema),
	}
	for _, c := range codes {
		responses[c] = openapi.JSONResponse("Auth-All error", openapi.Ref("ErrorResponse"))
	}
	return &openapi.Operation{
		OperationID: id,
		Summary:     summary,
		Tags:        tag,
		RequestBody: body,
		Responses:   responses,
		Client:      &openapi.ClientBinding{Namespace: "passkeys", Method: method},
	}
}

// created moves the success response of an operation to 201.
func created(op *openapi.Operation) *openapi.Operation {
	op.Responses["201"] = op.Responses["200"]
	delete(op.Responses, "200")
	return op
}

// withID adds the path parameter that names a passkey.
func withID(op *openapi.Operation) *openapi.Operation {
	op.Parameters = []openapi.Parameter{{Name: "id", In: "path", Required: true, Schema: openapi.String()}}
	return op
}

// guard requires a session principal. A passkey belongs to a person, so an API
// key never manages one.
func (p *Plugin) guard(fn func(http.ResponseWriter, *http.Request, *plugin.Principal)) http.Handler {
	gate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := p.principals.Current(r.Context())
		if principal == nil || principal.User == nil {
			p.writeError(w, r, apierr.ErrUnauthorized)
			return
		}
		if principal.Session == nil {
			p.writeError(w, r, apierr.ErrForbidden.WithMessage("Only a session can manage a passkey."))
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

// allowSignIn counts one sign-in attempt against the client address. A failed
// limiter is logged and lets the attempt through, as the core routes do.
func (p *Plugin) allowSignIn(w http.ResponseWriter, r *http.Request) bool {
	key := ratelimit.Key{Operation: ratelimit.OpPasskeySignIn, IP: p.svc.HTTP().ClientIP(r)}
	ok, err := p.svc.RateLimiter().Allow(r.Context(), key)
	if err != nil {
		p.svc.Logger().Error("authall/passkeys: the rate limiter failed", "error", err.Error())
		return true
	}
	if !ok {
		w.Header().Set("Retry-After", "60")
		p.writeError(w, r, apierr.ErrRateLimited)
		return false
	}
	return true
}

// handleRegisterBegin serves POST /passkeys/register/begin.
func (p *Plugin) handleRegisterBegin(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	if err := p.fresh(principal.Session); err != nil {
		p.writeError(w, r, err)
		return
	}
	handle, creation, err := p.beginRegistration(r.Context(), principal.User)
	if err != nil {
		p.writeError(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, beginResponse{Ceremony: handle, Options: creation})
}

// handleRegisterFinish serves POST /passkeys/register/finish.
func (p *Plugin) handleRegisterFinish(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	if err := p.fresh(principal.Session); err != nil {
		p.writeError(w, r, err)
		return
	}
	var req registerFinishRequest
	if err := p.svc.HTTP().DecodeJSON(r, &req); err != nil {
		p.writeError(w, r, err)
		return
	}
	key, err := p.finishRegistration(r.Context(), principal.User, req.Ceremony, req.Name, req.Credential)
	if err != nil {
		p.writeError(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusCreated, map[string]passkeyDTO{"passkey": toDTO(key)})
}

// handleSignInBegin serves POST /passkeys/sign-in/begin.
func (p *Plugin) handleSignInBegin(w http.ResponseWriter, r *http.Request) {
	if err := p.svc.HTTP().CheckOrigin(r); err != nil {
		p.writeError(w, r, err)
		return
	}
	if !p.allowSignIn(w, r) {
		return
	}
	handle, assertion, err := p.beginSignIn(r.Context())
	if err != nil {
		p.writeError(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, beginResponse{Ceremony: handle, Options: assertion})
}

// handleSignInFinish serves POST /passkeys/sign-in/finish.
func (p *Plugin) handleSignInFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := p.svc.HTTP().CheckOrigin(r); err != nil {
		p.writeError(w, r, err)
		return
	}
	if !p.allowSignIn(w, r) {
		return
	}
	var req signInFinishRequest
	if err := p.svc.HTTP().DecodeJSON(r, &req); err != nil {
		p.writeError(w, r, err)
		return
	}
	result, err := p.finishSignIn(ctx, req.Ceremony, req.Credential)
	if err != nil {
		p.writeError(w, r, err)
		return
	}
	if err := p.signIn.CheckSignIn(ctx, result.user); err != nil {
		p.writeError(w, r, err)
		return
	}
	if !result.verified {
		// Without user verification the passkey is one factor, so a user with
		// a confirmed second factor reaches a challenge and no session.
		challenge, required, err := p.svc.MFA().Challenge(ctx, result.user)
		if err != nil {
			p.writeError(w, r, err)
			return
		}
		if required {
			p.signIn.WriteAuthResponse(w, r, http.StatusOK, nil, nil, challenge)
			return
		}
	}
	sess, err := p.svc.Sessions().Issue(ctx, w, r, result.user, ID)
	if err != nil {
		p.writeError(w, r, err)
		return
	}
	p.signIn.WriteAuthResponse(w, r, http.StatusOK, result.user, sess, "")
}

// handleList serves GET /passkeys.
func (p *Plugin) handleList(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	keys, err := p.List(r.Context(), principal.User.ID)
	if err != nil {
		p.writeError(w, r, err)
		return
	}
	out := make([]passkeyDTO, 0, len(keys))
	for i := range keys {
		out = append(out, toDTO(&keys[i]))
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string][]passkeyDTO{"passkeys": out})
}

// handleDelete serves DELETE /passkeys/{id}.
func (p *Plugin) handleDelete(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	if err := p.fresh(principal.Session); err != nil {
		p.writeError(w, r, err)
		return
	}
	if err := p.Delete(r.Context(), principal.User.ID, r.PathValue("id")); err != nil {
		p.writeError(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

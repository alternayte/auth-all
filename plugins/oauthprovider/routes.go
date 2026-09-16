package oauthprovider

import (
	"context"
	"net/http"

	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/plugin"
)

// registerRoutes contributes every HTTP route of the plugin.
//
// The protocol routes carry no client binding, because a relying party speaks
// to them and the browser application does not. The host page routes carry
// one, so the generated TypeScript client holds them.
func (p *Plugin) registerRoutes(r *plugin.Registry) {
	protect := func(h http.HandlerFunc) http.Handler { return p.protect(h) }

	// A protocol route carries an operation and no client binding. A relying
	// party speaks to it, and the browser application does not, so the
	// generated TypeScript client holds no method for it.
	r.Route(plugin.Route{Method: http.MethodGet, Path: PathAuthorize,
		Handler:   http.HandlerFunc(p.handleAuthorize),
		Operation: protocolOperation("oauthProviderAuthorize", "Start the authorization code flow")})
	r.Route(plugin.Route{Method: http.MethodPost, Path: PathToken,
		Handler:   http.HandlerFunc(p.handleToken),
		Operation: protocolOperation("oauthProviderToken", "Exchange a code, a refresh token, or client credentials")})
	r.Route(plugin.Route{Method: http.MethodGet, Path: PathUserInfo,
		Handler:   http.HandlerFunc(p.handleUserInfo),
		Operation: protocolOperation("oauthProviderUserInfo", "Read the claims of an access token")})
	r.Route(plugin.Route{Method: http.MethodPost, Path: PathUserInfo,
		Handler:   http.HandlerFunc(p.handleUserInfo),
		Operation: protocolOperation("oauthProviderUserInfoPost", "Read the claims of an access token")})
	r.Route(plugin.Route{Method: http.MethodGet, Path: PathJWKS,
		Handler:   http.HandlerFunc(p.handleJWKS),
		Operation: protocolOperation("oauthProviderJWKS", "Read the published key set")})
	r.Route(plugin.Route{Method: http.MethodPost, Path: PathIntrospect,
		Handler:   http.HandlerFunc(p.handleIntrospect),
		Operation: protocolOperation("oauthProviderIntrospect", "Introspect one token")})
	r.Route(plugin.Route{Method: http.MethodPost, Path: PathRevoke,
		Handler:   http.HandlerFunc(p.handleRevoke),
		Operation: protocolOperation("oauthProviderRevoke", "Revoke one token")})
	// The metadata also answers under the base path, because a relying party
	// that ignores the path insertion of RFC 8414 looks there.
	r.Route(plugin.Route{Method: http.MethodGet, Path: "/.well-known/openid-configuration",
		Handler:   http.HandlerFunc(p.handleMetadataRoute),
		Operation: protocolOperation("oauthProviderOpenIDConfiguration", "Read the discovery document")})
	r.Route(plugin.Route{Method: http.MethodGet, Path: "/.well-known/oauth-authorization-server",
		Handler:   http.HandlerFunc(p.handleMetadataRoute),
		Operation: protocolOperation("oauthProviderServerMetadata", "Read the authorization server metadata")})

	if p.dynamic {
		r.Route(plugin.Route{Method: http.MethodPost, Path: PathRegister,
			Handler:   http.HandlerFunc(p.handleRegister),
			Operation: protocolOperation("oauthProviderRegister", "Register one client")})
		r.Route(plugin.Route{Method: http.MethodGet, Path: PathRegister + "/{clientID}",
			Handler:   http.HandlerFunc(p.handleReadClient),
			Operation: protocolOperation("oauthProviderReadRegistration", "Read one registered client")})
		r.Route(plugin.Route{Method: http.MethodPut, Path: PathRegister + "/{clientID}",
			Handler:   http.HandlerFunc(p.handleUpdateClient),
			Operation: protocolOperation("oauthProviderUpdateRegistration", "Update one registered client")})
		r.Route(plugin.Route{Method: http.MethodDelete, Path: PathRegister + "/{clientID}",
			Handler:   http.HandlerFunc(p.handleDeleteClient),
			Operation: protocolOperation("oauthProviderDeleteRegistration", "Remove one registered client")})
	}

	r.Route(plugin.Route{
		Method: http.MethodGet, Path: PathRequest,
		Handler: http.HandlerFunc(p.handleRequest),
		Operation: &openapi.Operation{
			OperationID: "oauthProviderRequest",
			Summary:     "Read one authorization request",
			Tags:        []string{"oauth-provider"},
			Parameters: []openapi.Parameter{
				{Name: "request_id", In: "query", Required: true, Description: "The authorization request.",
					Schema: &openapi.Schema{Type: "string"}},
			},
			Responses: map[string]openapi.Response{
				"200": openapi.JSONResponse("The authorization request.", requestSchema()),
			},
			Client: &openapi.ClientBinding{Namespace: "oauthProvider", Method: "request"},
		},
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: PathDecide,
		Handler: http.HandlerFunc(p.handleDecide),
		Operation: &openapi.Operation{
			OperationID: "oauthProviderDecide",
			Summary:     "Approve or deny one authorization request",
			Tags:        []string{"oauth-provider"},
			RequestBody: openapi.JSONBody(decisionSchema()),
			Responses: map[string]openapi.Response{
				"200": openapi.JSONResponse("The redirect target.", decisionResultSchema()),
			},
			Client: &openapi.ClientBinding{Namespace: "oauthProvider", Method: "decide"},
		},
	})
	r.Route(plugin.Route{
		Method: http.MethodGet, Path: PathConsents,
		Handler: protect(p.handleConsents),
		Operation: &openapi.Operation{
			OperationID: "oauthProviderConsents",
			Summary:     "List the standing consents of the user",
			Tags:        []string{"oauth-provider"},
			Responses: map[string]openapi.Response{
				"200": openapi.JSONResponse("The consents.", consentListSchema()),
			},
			Client: &openapi.ClientBinding{Namespace: "oauthProvider", Method: "consents"},
		},
	})
	r.Route(plugin.Route{
		Method: http.MethodDelete, Path: PathConsents + "/{clientID}",
		Handler: protect(p.handleWithdrawConsent),
		Operation: &openapi.Operation{
			OperationID: "oauthProviderWithdrawConsent",
			Summary:     "Withdraw the consent of one client",
			Tags:        []string{"oauth-provider"},
			Parameters: []openapi.Parameter{
				{Name: "clientID", In: "path", Required: true, Description: "The client.",
					Schema: &openapi.Schema{Type: "string"}},
			},
			Responses: map[string]openapi.Response{
				"200": openapi.JSONResponse("The withdrawal.", withdrawSchema()),
			},
			Client: &openapi.ClientBinding{Namespace: "oauthProvider", Method: "withdrawConsent"},
		},
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: PathClients,
		Handler: protect(p.handleCreateManagedClient),
		Operation: &openapi.Operation{
			OperationID: "oauthProviderCreateClient",
			Summary:     "Register one client as the signed-in user",
			Tags:        []string{"oauth-provider"},
			RequestBody: openapi.JSONBody(clientRequestSchema()),
			Responses: map[string]openapi.Response{
				"201": openapi.JSONResponse("The client.", managedClientSchema()),
			},
			Client: &openapi.ClientBinding{Namespace: "oauthProvider", Method: "createClient"},
		},
	})
	r.Route(plugin.Route{
		Method: http.MethodGet, Path: PathClients,
		Handler: protect(p.handleListManagedClients),
		Operation: &openapi.Operation{
			OperationID: "oauthProviderClients",
			Summary:     "List the clients of the signed-in user",
			Tags:        []string{"oauth-provider"},
			Responses: map[string]openapi.Response{
				"200": openapi.JSONResponse("The clients.", managedClientListSchema()),
			},
			Client: &openapi.ClientBinding{Namespace: "oauthProvider", Method: "clients"},
		},
	})
	r.Route(plugin.Route{
		Method: http.MethodDelete, Path: PathClients + "/{clientID}",
		Handler: protect(p.handleDeleteManagedClient),
		Operation: &openapi.Operation{
			OperationID: "oauthProviderDeleteClient",
			Summary:     "Remove one client of the signed-in user",
			Tags:        []string{"oauth-provider"},
			Parameters: []openapi.Parameter{
				{Name: "clientID", In: "path", Required: true, Description: "The client.",
					Schema: &openapi.Schema{Type: "string"}},
			},
			Responses: map[string]openapi.Response{
				"200": openapi.JSONResponse("The deletion.", deleteClientSchema()),
			},
			Client: &openapi.ClientBinding{Namespace: "oauthProvider", Method: "deleteClient"},
		},
	})
}

// handleMetadataRoute serves the metadata under the Auth-All base path.
func (p *Plugin) handleMetadataRoute(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	p.svc.HTTP().WriteJSON(w, http.StatusOK, p.metadata())
}

// registerHooks revokes the grants of a user whose authority changed.
//
// A revoked session revokes no token, because a browser sign-out must not end
// the offline access of an application. A disabled user and a deleted user
// revoke every grant, because their authority ended.
func (p *Plugin) registerHooks(r *plugin.Registry) {
	r.Hooks().OnAfterUserUpdate(func(ctx context.Context, ev *hook.UserUpdate) error {
		if ev == nil || ev.User == nil || ev.User.DisabledAt == nil {
			return nil
		}
		return p.rows.RevokeOAuthGrantsOfUser(ctx, ev.User.ID, p.now())
	})
}

package oauthprovider

import "github.com/alternayte/auth-all/openapi"

// The schemas of the host page routes and the management routes. The protocol
// routes carry no schema, because a relying party reads the metadata document
// and not the OpenAPI contract.

// protocolOperation documents one protocol route. The body of such a route
// follows its RFC, so the document names the route and its answer without a
// schema.
func protocolOperation(id, summary string) *openapi.Operation {
	return &openapi.Operation{
		OperationID: id,
		Summary:     summary,
		Tags:        []string{"oauth-provider"},
		Responses: map[string]openapi.Response{
			"200": openapi.JSONResponse("The answer of the route, as its RFC defines it.",
				&openapi.Schema{Type: "object"}),
		},
	}
}

func stringList() *openapi.Schema {
	return &openapi.Schema{Type: "array", Items: openapi.String()}
}

func requestSchema() *openapi.Schema {
	return openapi.Object(
		[]string{"requestId", "clientId", "clientName", "scopes", "firstParty", "needsSignIn", "consentGranted"},
		map[string]*openapi.Schema{
			"requestId":      openapi.String(),
			"clientId":       openapi.String(),
			"clientName":     openapi.String(),
			"logoUri":        openapi.String(),
			"scopes":         stringList(),
			"resources":      stringList(),
			"firstParty":     openapi.Bool(),
			"needsSignIn":    openapi.Bool(),
			"consentGranted": openapi.Bool(),
		})
}

func decisionSchema() *openapi.Schema {
	return openapi.Object([]string{"requestId", "approve"}, map[string]*openapi.Schema{
		"requestId": openapi.String(),
		"approve":   openapi.Bool(),
	})
}

func decisionResultSchema() *openapi.Schema {
	return openapi.Object([]string{"redirectTo"}, map[string]*openapi.Schema{
		"redirectTo": openapi.String(),
	})
}

func consentSchema() *openapi.Schema {
	return openapi.Object([]string{"clientId", "clientName", "scopes"}, map[string]*openapi.Schema{
		"clientId":   openapi.String(),
		"clientName": openapi.String(),
		"scopes":     stringList(),
		"resources":  stringList(),
	})
}

func consentListSchema() *openapi.Schema {
	return openapi.Object([]string{"consents"}, map[string]*openapi.Schema{
		"consents": {Type: "array", Items: consentSchema()},
	})
}

func withdrawSchema() *openapi.Schema {
	return openapi.Object([]string{"withdrawn"}, map[string]*openapi.Schema{
		"withdrawn": openapi.Bool(),
	})
}

func clientRequestSchema() *openapi.Schema {
	return openapi.Object([]string{"client_name", "redirect_uris"}, map[string]*openapi.Schema{
		"client_name":                openapi.String(),
		"redirect_uris":              stringList(),
		"grant_types":                stringList(),
		"response_types":             stringList(),
		"scope":                      openapi.String(),
		"token_endpoint_auth_method": openapi.String(),
		"logo_uri":                   openapi.String(),
		"dpop_bound_access_tokens":   openapi.Bool(),
	})
}

func managedClientSchema() *openapi.Schema {
	return openapi.Object(
		[]string{"clientId", "name", "redirectUris", "grantTypes", "scopes",
			"tokenEndpointAuthMethod", "dpopRequired", "createdAt"},
		map[string]*openapi.Schema{
			"clientId":                openapi.String(),
			"clientSecret":            openapi.String(),
			"name":                    openapi.String(),
			"redirectUris":            stringList(),
			"grantTypes":              stringList(),
			"scopes":                  stringList(),
			"tokenEndpointAuthMethod": openapi.String(),
			"dpopRequired":            openapi.Bool(),
			"createdAt":               openapi.String(),
		})
}

func managedClientListSchema() *openapi.Schema {
	return openapi.Object([]string{"clients"}, map[string]*openapi.Schema{
		"clients": {Type: "array", Items: managedClientSchema()},
	})
}

func deleteClientSchema() *openapi.Schema {
	return openapi.Object([]string{"deleted"}, map[string]*openapi.Schema{
		"deleted": openapi.Bool(),
	})
}

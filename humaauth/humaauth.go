// Package humaauth merges the Auth-All API into a huma document and protects a
// huma operation with a role.
//
// The package is a separate module, because the core Auth-All module adds no
// new dependency.
//
//	api := humago.New(mux, huma.DefaultConfig("Example", "1.0.0"))
//	if err := humaauth.Register(api, auth); err != nil { ... }
//	huma.Register(api, huma.Operation{
//	    OperationID: "deploy", Method: http.MethodPost, Path: "/deploy",
//	    Middlewares: huma.Middlewares{humaauth.RequireRole(api, auth, "operator")},
//	}, deployHandler)
package humaauth

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/openapi"
)

// Register adds every Auth-All operation and every Auth-All component schema to
// the huma document of api.
//
// It reports an error when an operation identifier, a path with the same
// method, or a schema name collides with a name of the host. A silent overwrite
// would give two different shapes for one name.
func Register(api huma.API, auth *authall.Auth) error {
	if api == nil || auth == nil {
		return fmt.Errorf("humaauth: the api and the Auth-All instance are required")
	}
	doc := api.OpenAPI()
	if doc == nil {
		return fmt.Errorf("humaauth: the api carries no OpenAPI document")
	}
	source := auth.OpenAPI()

	if err := checkOperationIDs(doc, source); err != nil {
		return err
	}
	if err := mergeSchemas(doc, source); err != nil {
		return err
	}
	return mergePaths(doc, source)
}

// checkOperationIDs reports an operation identifier that both documents use.
func checkOperationIDs(doc *huma.OpenAPI, source *openapi.Document) error {
	taken := map[string]string{}
	for path, item := range doc.Paths {
		if item == nil {
			continue
		}
		for method, op := range operationsOf(item) {
			if op != nil && op.OperationID != "" {
				taken[op.OperationID] = method + " " + path
			}
		}
	}
	for _, path := range sortedPaths(source) {
		for _, method := range sortedMethods(source.Paths[path]) {
			op := source.Paths[path][method]
			if op == nil || op.OperationID == "" {
				continue
			}
			if where, exists := taken[op.OperationID]; exists {
				return fmt.Errorf(
					"humaauth: the operation id %q exists already, at %s. Rename the host operation",
					op.OperationID, where)
			}
		}
	}
	return nil
}

// mergeSchemas copies the Auth-All component schemas into the huma registry.
func mergeSchemas(doc *huma.OpenAPI, source *openapi.Document) error {
	if doc.Components == nil {
		doc.Components = &huma.Components{}
	}
	if doc.Components.Schemas == nil {
		doc.Components.Schemas = huma.NewMapRegistry("#/components/schemas/", huma.DefaultSchemaNamer)
	}
	target := doc.Components.Schemas.Map()
	names := make([]string, 0, len(source.Components.Schemas))
	for name := range source.Components.Schemas {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, exists := target[name]; exists {
			return fmt.Errorf("humaauth: the schema name %q exists already. Rename the host schema", name)
		}
		target[name] = convertSchema(source.Components.Schemas[name])
	}
	return nil
}

// mergePaths copies the Auth-All operations into the huma document.
func mergePaths(doc *huma.OpenAPI, source *openapi.Document) error {
	if doc.Paths == nil {
		doc.Paths = map[string]*huma.PathItem{}
	}
	for _, path := range sortedPaths(source) {
		item, ok := doc.Paths[path]
		if !ok || item == nil {
			item = &huma.PathItem{}
			doc.Paths[path] = item
		}
		for _, method := range sortedMethods(source.Paths[path]) {
			op := convertOperation(source.Paths[path][method])
			existing := operationsOf(item)[strings.ToUpper(method)]
			if existing != nil {
				return fmt.Errorf("humaauth: the route %s %s exists already. Move the host route",
					strings.ToUpper(method), path)
			}
			if err := setOperation(item, method, op); err != nil {
				return err
			}
		}
	}
	return nil
}

// operationsOf returns the operations of one path item by method.
func operationsOf(item *huma.PathItem) map[string]*huma.Operation {
	return map[string]*huma.Operation{
		http.MethodGet:    item.Get,
		http.MethodPost:   item.Post,
		http.MethodPut:    item.Put,
		http.MethodPatch:  item.Patch,
		http.MethodDelete: item.Delete,
	}
}

// setOperation puts one operation in the path item.
func setOperation(item *huma.PathItem, method string, op *huma.Operation) error {
	switch strings.ToUpper(method) {
	case http.MethodGet:
		item.Get = op
	case http.MethodPost:
		item.Post = op
	case http.MethodPut:
		item.Put = op
	case http.MethodPatch:
		item.Patch = op
	case http.MethodDelete:
		item.Delete = op
	default:
		return fmt.Errorf("humaauth: the method %q is not supported", method)
	}
	return nil
}

// convertOperation returns the huma shape of one Auth-All operation.
func convertOperation(op *openapi.Operation) *huma.Operation {
	out := &huma.Operation{
		OperationID: op.OperationID,
		Summary:     op.Summary,
		Description: op.Description,
		Tags:        op.Tags,
		Responses:   map[string]*huma.Response{},
	}
	for _, p := range op.Parameters {
		out.Parameters = append(out.Parameters, &huma.Param{
			Name:        p.Name,
			In:          p.In,
			Required:    p.Required,
			Description: p.Description,
			Schema:      convertSchema(p.Schema),
		})
	}
	if op.RequestBody != nil {
		out.RequestBody = &huma.RequestBody{
			Required: op.RequestBody.Required,
			Content:  convertContent(op.RequestBody.Content),
		}
	}
	for status, response := range op.Responses {
		out.Responses[status] = &huma.Response{
			Description: response.Description,
			Content:     convertContent(response.Content),
		}
	}
	return out
}

// convertContent returns the huma shape of one content map.
func convertContent(content map[string]openapi.MediaType) map[string]*huma.MediaType {
	if len(content) == 0 {
		return nil
	}
	out := map[string]*huma.MediaType{}
	for name, media := range content {
		out[name] = &huma.MediaType{Schema: convertSchema(media.Schema)}
	}
	return out
}

// convertSchema returns the huma shape of one Auth-All schema.
func convertSchema(s *openapi.Schema) *huma.Schema {
	if s == nil {
		return nil
	}
	out := &huma.Schema{
		Type:        s.Type,
		Format:      s.Format,
		Description: s.Description,
		Ref:         s.Ref,
		Required:    s.Required,
	}
	for _, value := range s.Enum {
		out.Enum = append(out.Enum, value)
	}
	if s.Items != nil {
		out.Items = convertSchema(s.Items)
	}
	if len(s.Properties) > 0 {
		out.Properties = map[string]*huma.Schema{}
		for name, property := range s.Properties {
			out.Properties[name] = convertSchema(property)
		}
	}
	return out
}

// sortedPaths returns the paths of one document in a deterministic order.
func sortedPaths(doc *openapi.Document) []string {
	out := make([]string, 0, len(doc.Paths))
	for path := range doc.Paths {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// sortedMethods returns the methods of one path in a deterministic order.
func sortedMethods(item map[string]*openapi.Operation) []string {
	out := make([]string, 0, len(item))
	for method := range item {
		out = append(out, method)
	}
	sort.Strings(out)
	return out
}

// RequireRole returns a huma middleware that refuses a request whose effective
// role ranks below min.
//
// The middleware has the same result as roles.Require: a request with no
// principal gets 401 UNAUTHORIZED, and a lower role gets 403
// INSUFFICIENT_ROLE. It panics when min is not a configured role.
func RequireRole(api huma.API, auth *authall.Auth, min string) func(huma.Context, func(huma.Context)) {
	if !known(auth, min) {
		panic(fmt.Sprintf("humaauth: the minimum role %q is not configured. Configured: %v",
			min, auth.RoleNames()))
	}
	return func(ctx huma.Context, next func(huma.Context)) {
		principal := authall.PrincipalFrom(ctx.Context())
		if principal == nil {
			writeError(api, ctx, apierr.ErrUnauthorized)
			return
		}
		if !auth.RoleAtLeast(principal.Role, min) {
			writeError(api, ctx, apierr.ErrInsufficientRole)
			return
		}
		next(ctx)
	}
}

// writeError writes one Auth-All error through the huma error writer.
func writeError(api huma.API, ctx huma.Context, e *apierr.Error) {
	_ = huma.WriteErr(api, ctx, e.Status, string(e.Code))
}

// known reports whether the instance names the role.
func known(auth *authall.Auth, role string) bool {
	for _, name := range auth.RoleNames() {
		if name == role {
			return true
		}
	}
	return false
}

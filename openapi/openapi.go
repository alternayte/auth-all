// Package openapi holds the OpenAPI document model of Auth-All. Core and
// plugins contribute operations. The document drives the generated TypeScript
// client and the published API contract.
package openapi

// Document is an OpenAPI 3.0.3 document.
type Document struct {
	OpenAPI    string              `json:"openapi"`
	Info       Info                `json:"info"`
	Servers    []Server            `json:"servers,omitempty"`
	Paths      map[string]PathItem `json:"paths"`
	Components Components          `json:"components"`
}

// Info describes the API.
type Info struct {
	Title       string `json:"title"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
}

// Server is one base URL.
type Server struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}

// PathItem maps a lowercase HTTP method to one operation.
type PathItem map[string]*Operation

// Components holds reusable schemas.
type Components struct {
	Schemas map[string]*Schema `json:"schemas,omitempty"`
}

// Operation is one HTTP operation.
type Operation struct {
	OperationID string              `json:"operationId"`
	Summary     string              `json:"summary,omitempty"`
	Description string              `json:"description,omitempty"`
	Tags        []string            `json:"tags,omitempty"`
	Parameters  []Parameter         `json:"parameters,omitempty"`
	RequestBody *RequestBody        `json:"requestBody,omitempty"`
	Responses   map[string]Response `json:"responses"`
	Client      *ClientBinding      `json:"x-authall-client,omitempty"`
}

// ClientBinding tells the client generator how to expose one operation.
//
// A namespace groups methods, so a binding of namespace "signIn" and method
// "email" becomes auth.signIn.email(...) in the generated TypeScript client.
type ClientBinding struct {
	Namespace string `json:"namespace,omitempty"`
	Method    string `json:"method"`
	// Redirect marks an operation that a browser follows instead of fetching.
	Redirect bool `json:"redirect,omitempty"`
}

// Parameter is one query or path parameter.
type Parameter struct {
	Name        string  `json:"name"`
	In          string  `json:"in"`
	Required    bool    `json:"required,omitempty"`
	Description string  `json:"description,omitempty"`
	Schema      *Schema `json:"schema,omitempty"`
}

// RequestBody is a JSON request body.
type RequestBody struct {
	Required bool                 `json:"required,omitempty"`
	Content  map[string]MediaType `json:"content"`
}

// Response is one response.
type Response struct {
	Description string               `json:"description"`
	Content     map[string]MediaType `json:"content,omitempty"`
}

// MediaType binds a schema to a content type.
type MediaType struct {
	Schema *Schema `json:"schema,omitempty"`
}

// Schema is a JSON schema subset.
type Schema struct {
	Ref                  string             `json:"$ref,omitempty"`
	Type                 string             `json:"type,omitempty"`
	Format               string             `json:"format,omitempty"`
	Description          string             `json:"description,omitempty"`
	Nullable             bool               `json:"nullable,omitempty"`
	Properties           map[string]*Schema `json:"properties,omitempty"`
	Required             []string           `json:"required,omitempty"`
	Items                *Schema            `json:"items,omitempty"`
	Enum                 []string           `json:"enum,omitempty"`
	AdditionalProperties *Schema            `json:"additionalProperties,omitempty"`
}

// JSONBody returns a required JSON request body for one schema.
func JSONBody(s *Schema) *RequestBody {
	return &RequestBody{Required: true, Content: map[string]MediaType{"application/json": {Schema: s}}}
}

// JSONResponse returns a JSON response for one schema.
func JSONResponse(description string, s *Schema) Response {
	return Response{Description: description, Content: map[string]MediaType{"application/json": {Schema: s}}}
}

// Ref returns a reference to a component schema.
func Ref(name string) *Schema { return &Schema{Ref: "#/components/schemas/" + name} }

// Object returns an object schema.
func Object(required []string, props map[string]*Schema) *Schema {
	return &Schema{Type: "object", Required: required, Properties: props}
}

// String returns a string schema.
func String() *Schema { return &Schema{Type: "string"} }

// Bool returns a boolean schema.
func Bool() *Schema { return &Schema{Type: "boolean"} }

// New returns an empty document.
func New(title, version string) *Document {
	return &Document{
		OpenAPI:    "3.0.3",
		Info:       Info{Title: title, Version: version},
		Paths:      map[string]PathItem{},
		Components: Components{Schemas: map[string]*Schema{}},
	}
}

// AddOperation registers one operation. A duplicate method and path pair
// replaces the previous entry.
func (d *Document) AddOperation(method, path string, op *Operation) {
	if d.Paths == nil {
		d.Paths = map[string]PathItem{}
	}
	item, ok := d.Paths[path]
	if !ok {
		item = PathItem{}
		d.Paths[path] = item
	}
	item[lower(method)] = op
}

// AddSchema registers one reusable component schema.
func (d *Document) AddSchema(name string, s *Schema) {
	if d.Components.Schemas == nil {
		d.Components.Schemas = map[string]*Schema{}
	}
	d.Components.Schemas[name] = s
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

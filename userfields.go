package authall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/alternayte/auth-all/apierr"

	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// Field returns the value of one host-owned user field.
//
// It reports an error when the field is absent, and when the stored value has
// another type than T.
//
//	team, err := authall.Field[string](user, "team")
func Field[T any](user *store.User, name string) (T, error) {
	var zero T
	if user == nil {
		return zero, fmt.Errorf("authall: the user is nil")
	}
	raw, ok := user.Extra.Get(name)
	if !ok {
		return zero, fmt.Errorf("authall: the user field %q is not declared. Use authall.WithUserFields", name)
	}
	if raw == nil {
		// A null column gives the zero value and no error, so a nullable field
		// needs no second call.
		return zero, nil
	}
	if value, ok := raw.(T); ok {
		return value, nil
	}
	// A driver can return another numeric or time shape, so one conversion
	// round makes the common pairs work.
	if converted, ok := convertField[T](raw); ok {
		return converted, nil
	}
	return zero, fmt.Errorf("authall: the user field %q holds %T, and the caller asked for %T", name, raw, zero)
}

// convertField converts the common driver shapes into the asked type.
func convertField[T any](raw any) (T, bool) {
	var zero T
	switch target := any(&zero).(type) {
	case *int64:
		switch v := raw.(type) {
		case int:
			*target = int64(v)
			return zero, true
		case int32:
			*target = int64(v)
			return zero, true
		}
	case *bool:
		if v, ok := raw.(int64); ok {
			// SQLite has no boolean type, so it returns 0 or 1.
			*target = v != 0
			return zero, true
		}
	case *string:
		if v, ok := raw.([]byte); ok {
			*target = string(v)
			return zero, true
		}
	case *time.Time:
		if v, ok := raw.(string); ok {
			parsed, err := time.Parse("2006-01-02T15:04:05.000000000", v)
			if err != nil {
				return zero, false
			}
			*target = parsed
			return zero, true
		}
	}
	return zero, false
}

// UserFields returns the declared host-owned user fields.
func (a *Auth) UserFields() []schema.UserField {
	return append([]schema.UserField(nil), a.cfg.schemaOptions.UserFields...)
}

// inputFields returns the fields that a route can write.
func (a *Auth) inputFields() []schema.UserField {
	var out []schema.UserField
	for _, f := range a.cfg.schemaOptions.UserFields {
		if f.Input {
			out = append(out, f)
		}
	}
	return out
}

// returnedFields returns the fields that a response can carry.
func (a *Auth) returnedFields() []schema.UserField {
	var out []schema.UserField
	for _, f := range a.cfg.schemaOptions.UserFields {
		if f.Returned {
			out = append(out, f)
		}
	}
	return out
}

// readInputFields returns the declared input fields of a request body. A field
// with Input false never reaches the store.
func (a *Auth) readInputFields(raw []byte) map[string]any {
	fields := a.inputFields()
	if len(fields) == 0 || len(raw) == 0 {
		return nil
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil
	}
	out := map[string]any{}
	for _, f := range fields {
		value, ok := body[f.Name]
		if !ok {
			continue
		}
		converted, ok := decodeField(f, value)
		if !ok {
			continue
		}
		out[f.Name] = converted
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// decodeField reads one JSON value in the declared type of a field.
func decodeField(f schema.UserField, raw json.RawMessage) (any, bool) {
	switch f.Type {
	case schema.TypeText:
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, false
		}
		return value, true
	case schema.TypeInt:
		var value int64
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, false
		}
		return value, true
	case schema.TypeBool:
		var value bool
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, false
		}
		return value, true
	case schema.TypeTimestamp:
		var value time.Time
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, false
		}
		return value, true
	}
	return nil, false
}

// decodeWithUserFields reads a JSON request body that can carry the declared
// user fields.
//
// A declared field never reaches the strict decoder, so an unknown field still
// fails the request. A field with Input false is read and dropped, so a route
// ignores it.
func (a *Auth) decodeWithUserFields(r *http.Request, dst any) (map[string]any, error) {
	declared := a.cfg.schemaOptions.UserFields
	if len(declared) == 0 {
		return nil, a.decodeJSON(r, dst)
	}
	if r.Body == nil {
		return nil, apierr.ErrInvalidRequest
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		return nil, apierr.ErrInvalidRequest.WithCause(err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, apierr.ErrInvalidRequest.WithCause(err)
	}
	for _, f := range declared {
		delete(body, f.Name)
	}
	rest, err := json.Marshal(body)
	if err != nil {
		return nil, apierr.ErrInvalidRequest.WithCause(err)
	}
	dec := json.NewDecoder(bytes.NewReader(rest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return nil, apierr.ErrInvalidRequest.WithCause(err)
	}
	return a.readInputFields(raw), nil
}

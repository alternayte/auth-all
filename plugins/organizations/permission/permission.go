// Package permission holds the permission statements of Auth-All.
//
// A statement is the string "resource:action". A wildcard replaces one whole
// segment, and the single asterisk names every permission.
//
//	project:read      one action of one resource
//	project:*         every action of the resource
//	*:read            the read action of every resource
//	*                 every permission
//
// The evaluation runs no regular expression, and it reads no pattern from a
// request. A check costs a small, fixed number of map lookups, so it needs no
// store access and no network call.
package permission

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Wildcard is the segment that matches every value of one segment.
const Wildcard = "*"

// ErrInvalid reports a statement that the grammar refuses.
var ErrInvalid = errors.New("authall/permission: the statement is invalid")

// Statement is one validated permission of the form "resource:action". The
// single asterisk is the statement that names every permission.
type Statement struct {
	resource string
	action   string
	all      bool
}

// Parse returns the statement of s.
//
// The grammar accepts the single asterisk, or two segments that a colon
// separates. A segment holds at least one character of [a-z0-9_.-], or it is
// the single asterisk. Every other input fails with ErrInvalid.
func Parse(s string) (Statement, error) {
	if s == Wildcard {
		return Statement{all: true}, nil
	}
	resource, action, found := strings.Cut(s, ":")
	if !found {
		return Statement{}, fmt.Errorf("%w: %q needs the form resource:action", ErrInvalid, s)
	}
	if err := validSegment(resource); err != nil {
		return Statement{}, fmt.Errorf("%w: %q has an invalid resource: %s", ErrInvalid, s, err)
	}
	if err := validSegment(action); err != nil {
		return Statement{}, fmt.Errorf("%w: %q has an invalid action: %s", ErrInvalid, s, err)
	}
	return Statement{resource: resource, action: action}, nil
}

// MustParse returns the statement of s, and it panics when s is invalid. Use
// it for a constant of the application, so a wrong statement fails at the
// start and not on a request.
func MustParse(s string) Statement {
	stmt, err := Parse(s)
	if err != nil {
		panic(err.Error())
	}
	return stmt
}

// validSegment reports whether one segment follows the grammar. The asterisk
// stands alone, so "pro*ject" is invalid.
func validSegment(seg string) error {
	if seg == Wildcard {
		return nil
	}
	if seg == "" {
		return errors.New("a segment is empty")
	}
	for _, r := range seg {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == '-':
		default:
			return fmt.Errorf("the character %q is not allowed", r)
		}
	}
	return nil
}

// String returns the statement in its written form.
func (s Statement) String() string {
	if s.all {
		return Wildcard
	}
	return s.resource + ":" + s.action
}

// Set is a set of statements. The zero value holds no permission, so it denies
// every check.
type Set struct {
	all     bool
	grants  map[Statement]struct{}
	sources []string
}

// NewSet returns the set of the given statements. It fails on the first
// statement that the grammar refuses.
func NewSet(statements ...string) (Set, error) {
	var set Set
	for _, raw := range statements {
		stmt, err := Parse(raw)
		if err != nil {
			return Set{}, err
		}
		set.add(stmt)
	}
	return set, nil
}

// MustNewSet returns the set of the given statements, and it panics on an
// invalid statement.
func MustNewSet(statements ...string) Set {
	set, err := NewSet(statements...)
	if err != nil {
		panic(err.Error())
	}
	return set
}

// add puts one statement in the set.
func (s *Set) add(stmt Statement) {
	if stmt.all {
		s.all = true
	}
	if s.grants == nil {
		s.grants = make(map[Statement]struct{})
	}
	if _, held := s.grants[stmt]; held {
		return
	}
	s.grants[stmt] = struct{}{}
	s.sources = append(s.sources, stmt.String())
}

// Empty reports whether the set holds no statement.
func (s Set) Empty() bool { return len(s.grants) == 0 }

// Statements returns the written statements of the set, in sorted order.
func (s Set) Statements() []string {
	out := append([]string(nil), s.sources...)
	sort.Strings(out)
	return out
}

// Allows reports whether the set holds the asked permission.
//
// The check is default deny. A statement that the grammar refuses is denied,
// and so is a statement of a set that holds nothing. A held wildcard covers
// the segment that it replaces, so "project:*" allows "project:read".
func (s Set) Allows(statement string) bool {
	stmt, err := Parse(statement)
	if err != nil {
		return false
	}
	return s.Covers(stmt)
}

// Covers reports whether the set holds the whole reach of stmt.
//
// A concrete statement needs one grant that matches it. A wildcard statement
// needs a grant of the same reach or of a wider reach, so a set of
// "project:read" alone does not cover "project:*". This is the rule that stops
// a privilege escalation through a custom role.
func (s Set) Covers(stmt Statement) bool {
	if s.all {
		return true
	}
	if len(s.grants) == 0 {
		return false
	}
	if _, held := s.grants[stmt]; held {
		return true
	}
	if stmt.all {
		// Only the single asterisk covers every permission, and the set does
		// not hold it.
		return false
	}
	if stmt.resource != Wildcard {
		if _, held := s.grants[Statement{resource: stmt.resource, action: Wildcard}]; held {
			return true
		}
	}
	if stmt.action != Wildcard {
		if _, held := s.grants[Statement{resource: Wildcard, action: stmt.action}]; held {
			return true
		}
	}
	return false
}

// Union returns the set that holds every statement of s and of others. The
// effective permissions of a member are the union of the organization role and
// of every team role.
func (s Set) Union(others ...Set) Set {
	var out Set
	for stmt := range s.grants {
		out.add(stmt)
	}
	for _, other := range others {
		for stmt := range other.grants {
			out.add(stmt)
		}
	}
	return out
}

// CoversSet reports whether s holds the whole reach of every statement of
// other. A member grants a role only when this reports true.
func (s Set) CoversSet(other Set) bool {
	for stmt := range other.grants {
		if !s.Covers(stmt) {
			return false
		}
	}
	return true
}

// Package conditions builds conditional ACE expressions and compiles SDDL on
// Windows. Syntax validation does not prove that claims exist in an AD schema or
// that a descriptor is appropriate for an authentication policy.
package conditions

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	ErrInvalidExpression = errors.New("invalid conditional expression")
	ErrUnsupported       = errors.New("native conditional SDDL requires Windows amd64 or arm64")
)

// Scope identifies a Windows conditional-ACE claim namespace.
type Scope string

const (
	User     Scope = "User"
	Device   Scope = "Device"
	Resource Scope = "Resource"
)

// Claim names are validated independently of values to prevent syntax injection.
type Claim struct {
	Scope Scope
	Name  string
}

func (c Claim) render() (string, error) {
	if c.Scope != User && c.Scope != Device && c.Scope != Resource {
		return "", fmt.Errorf("%w: unsupported claim scope", ErrInvalidExpression)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_:/\.]+$`).MatchString(c.Name) {
		return "", fmt.Errorf("%w: invalid claim name", ErrInvalidExpression)
	}
	return "@" + string(c.Scope) + "." + c.Name, nil
}

// Value is a literal or claim reference. Its zero value is invalid.
type Value struct {
	text string
	err  error
}

// Text constructs a quoted literal. Double quotes, NUL, and control characters
// are rejected rather than assuming Go/JSON escape sequences work in Windows
// conditional expressions. Backslashes and percent characters remain literal.
func Text(value string) Value {
	if !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\"\r\n\t") {
		return Value{err: fmt.Errorf("%w: string literal contains unsupported characters", ErrInvalidExpression)}
	}
	for _, r := range value {
		if r < 0x20 {
			return Value{err: fmt.Errorf("%w: string literal contains control characters", ErrInvalidExpression)}
		}
	}
	return Value{text: `"` + value + `"`}
}
func Integer(value int64) Value   { return Value{text: strconv.FormatInt(value, 10)} }
func Reference(claim Claim) Value { text, err := claim.render(); return Value{text: text, err: err} }

type Operator string

const (
	Equal          Operator = "=="
	NotEqual       Operator = "!="
	Less           Operator = "<"
	LessOrEqual    Operator = "<="
	Greater        Operator = ">"
	GreaterOrEqual Operator = ">="
	Contains       Operator = "Contains"
	AnyOf          Operator = "Any_of"
)

// Expression is constructed through typed builders or Raw. The zero value is
// invalid. Builders retain errors until Render or Compile is called.
type Expression struct {
	text string
	err  error
}

func Compare(claim Claim, op Operator, value Value) Expression {
	name, err := claim.render()
	if err != nil {
		return Expression{err: err}
	}
	if value.err != nil {
		return Expression{err: value.err}
	}
	if value.text == "" {
		return Expression{err: fmt.Errorf("%w: missing value", ErrInvalidExpression)}
	}
	switch op {
	case Equal, NotEqual, Less, LessOrEqual, Greater, GreaterOrEqual, Contains, AnyOf:
	default:
		return Expression{err: fmt.Errorf("%w: unsupported comparison operator", ErrInvalidExpression)}
	}
	return Expression{text: "(" + name + " " + string(op) + " " + value.text + ")"}
}

func Exists(claim Claim) Expression {
	name, err := claim.render()
	if err != nil {
		return Expression{err: err}
	}
	return Expression{text: "(Exists " + name + ")"}
}

// MemberOf tests token membership. SIDs must be canonical numeric SID strings;
// Windows validates the SID ranges when compiling the expression.
func MemberOf(device bool, sids ...string) Expression {
	if len(sids) == 0 {
		return Expression{err: fmt.Errorf("%w: membership needs SIDs", ErrInvalidExpression)}
	}
	values := make([]string, len(sids))
	for n, sid := range sids {
		if !regexp.MustCompile(`^S-1-[0-9]+(?:-[0-9]+)+$`).MatchString(sid) {
			return Expression{err: fmt.Errorf("%w: malformed SID", ErrInvalidExpression)}
		}
		values[n] = "SID(" + sid + ")"
	}
	op := "Member_of"
	if device {
		op = "Device_Member_of"
	}
	return Expression{text: "(" + op + " {" + strings.Join(values, ", ") + "})"}
}

func All(expressions ...Expression) Expression { return combine("&&", expressions) }
func Any(expressions ...Expression) Expression { return combine("||", expressions) }
func combine(op string, expressions []Expression) Expression {
	if len(expressions) < 2 {
		return Expression{err: fmt.Errorf("%w: boolean composition needs at least two operands", ErrInvalidExpression)}
	}
	parts := make([]string, len(expressions))
	for n, e := range expressions {
		s, err := e.Render()
		if err != nil {
			return Expression{err: err}
		}
		parts[n] = s
	}
	return Expression{text: "(" + strings.Join(parts, " "+op+" ") + ")"}
}
func Not(expression Expression) Expression {
	text, err := expression.Render()
	if err != nil {
		return Expression{err: err}
	}
	return Expression{text: "(!" + text + ")"}
}

// Raw opts into the native condition language. Render only checks encoding and
// boundaries; Compile performs Windows syntax validation. This is not a shell.
func Raw(condition string) Expression {
	if !validInput(condition) {
		return Expression{err: fmt.Errorf("%w: condition is empty, too long, or not NUL-free UTF-8", ErrInvalidExpression)}
	}
	return Expression{text: condition}
}
func validInput(s string) bool {
	return strings.TrimSpace(s) != "" && len(s) <= 65535 && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}
func (e Expression) Render() (string, error) {
	if e.err != nil {
		return "", e.err
	}
	if !validInput(e.text) {
		return "", fmt.Errorf("%w: empty or oversized expression", ErrInvalidExpression)
	}
	return e.text, nil
}

// ACE describes one explicitly scoped access condition. There is no default
// access mask or trustee: callers must choose the rights and identity to grant.
type ACE struct {
	TrusteeSID string
	AccessMask uint32
	Deny       bool
	Condition  Expression
}

func (a ACE) validate() (string, error) {
	if !regexp.MustCompile(`^S-1-[0-9]+(?:-[0-9]+)+$`).MatchString(a.TrusteeSID) {
		return "", fmt.Errorf("%w: numeric trustee SID required", ErrInvalidExpression)
	}
	if a.AccessMask == 0 {
		return "", fmt.Errorf("%w: nonzero explicit access mask required", ErrInvalidExpression)
	}
	return a.Condition.Render()
}

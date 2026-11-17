package model

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ErrADFilterSyntax     = errors.New("invalid AD filter expression")
	ErrADFilterVariable   = errors.New("missing or invalid AD filter variable")
	ErrADFilterConversion = errors.New("AD filter value cannot be converted for this property")
	ErrADFilterProperty   = errors.New("AD filter property requires an explicit supported mapping")
)

// ADFilterError locates a rejected expression without echoing assertion values.
// Offset is a zero-based UTF-8 byte offset; Line and Column are one-based, with
// Column counting Unicode code points. Cause supports errors.Is/errors.As.
type ADFilterError struct {
	Offset, Line, Column int
	Reason               string
	Cause                error
}

func (e *ADFilterError) Error() string {
	return fmt.Sprintf("AD filter at %d:%d (byte %d): %s", e.Line, e.Column, e.Offset, e.Reason)
}
func (e *ADFilterError) Unwrap() error { return e.Cause }

// ADFilterProfile selects property aliases, not search base, object class, or
// scope. Account/user/computer/group profiles are specifically AD DS mappings.
// AD LDS callers use common object aliases and explicit schema descriptors.
type ADFilterProfile uint8

const (
	ADFilterObject ADFilterProfile = iota
	ADFilterUser
	ADFilterComputer
	ADFilterGroup
)

type ADFilterSyntax uint8

const (
	ADFilterScalar ADFilterSyntax = iota // explicit string, number, boolean or binary Go value
	ADFilterString
	ADFilterBoolean
	ADFilterInteger
	ADFilterBinary
	ADFilterGUID
	ADFilterSID
	ADFilterFileTime
	ADFilterGeneralizedTime
)

// ADFilterProperty maps an expression property to a known LDAP attribute and
// syntax. Descriptors are caller-supplied schema facts, not directory discovery.
type ADFilterProperty struct {
	Attribute string
	Syntax    ADFilterSyntax
}

type ADFilterOptions struct {
	Profile ADFilterProfile
	// Names omit '$' and are case-insensitive. Duplicate folded names and
	// overriding true/false/null are rejected. Nil is not an absence predicate.
	Variables map[string]any
	// Properties adds or overrides direct mappings, including schema extensions.
	// A descriptor cannot silently replace a built-in computed property.
	Properties map[string]ADFilterProperty
}

// ParseADFilter parses the AD expression language and returns a typed LDAP
// filter. It never evaluates PowerShell, commands, interpolation, property or
// method access. Go variables are bound as values, never textually substituted.
// Pass the result to SearchOptions.TypedFilter. Parentheses and one optional
// outer brace pair are grouping syntax only; a standalone '*' means match all.
func ParseADFilter(expression string, options ADFilterOptions) (Filter, error) {
	p := InternalAdExpressionParser{InternalSource: expression}
	if len(expression) > MaxFilterBytes {
		return Filter{}, p.InternalFailure(0, "expression exceeds size limit", ErrFilterLimit)
	}
	if !utf8.ValidString(expression) || strings.ContainsRune(expression, 0) {
		return Filter{}, p.InternalFailure(
			0,
			"expression must be UTF-8 without literal NUL",
			ErrADFilterSyntax,
		)
	}
	if options.Profile > ADFilterGroup {
		return Filter{}, p.InternalFailure(0, "unknown property profile", ErrADFilterProperty)
	}
	if err := p.InternalNext(); err != nil {
		return Filter{}, err
	}
	braced := p.InternalToken.InternalKind == '{'
	if braced {
		if err := p.InternalNext(); err != nil {
			return Filter{}, err
		}
	}
	var node *InternalAdExpressionNode
	var err error
	if p.InternalToken.InternalKind == '*' {
		node = &InternalAdExpressionNode{
			InternalOp:  "all",
			InternalPos: p.InternalToken.InternalPos,
		}
		err = p.InternalNext()
	} else {
		node, err = p.InternalParseOr(0)
	}
	if err != nil {
		return Filter{}, err
	}
	if braced {
		if p.InternalToken.InternalKind != '}' {
			return Filter{}, p.InternalFailure(
				p.InternalToken.InternalPos,
				"expected closing brace",
				ErrADFilterSyntax,
			)
		}
		if err = p.InternalNext(); err != nil {
			return Filter{}, err
		}
	}
	if p.InternalToken.InternalKind != 0 {
		return Filter{}, p.InternalFailure(
			p.InternalToken.InternalPos,
			"unexpected token after expression",
			ErrADFilterSyntax,
		)
	}
	binder, err := InternalNewADFilterBinder(&p, options)
	if err != nil {
		return Filter{}, err
	}
	return binder.InternalCompile(node)
}

type InternalAdExpressionNode struct {
	InternalOp, InternalAttribute string
	InternalValue                 InternalAdExpressionToken
	InternalChildren              []*InternalAdExpressionNode
	InternalPos                   int
}
type InternalAdExpressionToken struct {
	InternalKind byte
	InternalText string
	InternalPos  int
}
type InternalAdExpressionParser struct {
	InternalSource                 string
	InternalOffset, InternalTokens int
	InternalToken                  InternalAdExpressionToken
}

func (p *InternalAdExpressionParser) InternalFailure(pos int, reason string, cause error) error {
	line, column := 1, 1
	for _, r := range p.InternalSource[:min(pos, len(p.InternalSource))] {
		if r == '\n' {
			line++
			column = 1
		} else {
			column++
		}
	}
	return &ADFilterError{Offset: pos, Line: line, Column: column, Reason: reason, Cause: cause}
}

func InternalAdNameStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}
func InternalAdDigit(c byte) bool    { return c >= '0' && c <= '9' }
func InternalAdNamePart(c byte) bool { return InternalAdNameStart(c) || InternalAdDigit(c) }

func (p *InternalAdExpressionParser) InternalNext() error {
	for p.InternalOffset < len(p.InternalSource) {
		r, size := utf8.DecodeRuneInString(p.InternalSource[p.InternalOffset:])
		if !unicode.IsSpace(r) {
			break
		}
		p.InternalOffset += size
	}
	start := p.InternalOffset
	p.InternalToken = InternalAdExpressionToken{InternalPos: start}
	p.InternalTokens++
	if p.InternalTokens > 8192 {
		return p.InternalFailure(start, "expression exceeds token limit", ErrFilterLimit)
	}
	if start == len(p.InternalSource) {
		return nil
	}
	c := p.InternalSource[p.InternalOffset]
	p.InternalOffset++
	if strings.ContainsRune("(){}*", rune(c)) {
		p.InternalToken.InternalKind = c
		return nil
	}
	if c == '\'' || c == '"' {
		var value strings.Builder
		for p.InternalOffset < len(p.InternalSource) {
			v := p.InternalSource[p.InternalOffset]
			p.InternalOffset++
			if v == c {
				if c == '\'' && p.InternalOffset < len(p.InternalSource) &&
					p.InternalSource[p.InternalOffset] == '\'' {
					value.WriteByte(c)
					p.InternalOffset++
					continue
				}
				p.InternalToken.InternalKind = 's'
				p.InternalToken.InternalText = value.String()
				return nil
			}
			if c == '"' && v == '`' {
				// Only backtick-quote is special in the AD parser. Other
				// backticks remain data; PowerShell interpolation is not run.
				if p.InternalOffset < len(p.InternalSource) &&
					p.InternalSource[p.InternalOffset] == '"' {
					v = '"'
					p.InternalOffset++
				}
			}
			value.WriteByte(v)
		}
		return p.InternalFailure(start, "unterminated quoted value", ErrADFilterSyntax)
	}
	if c == '$' {
		braced := p.InternalOffset < len(p.InternalSource) &&
			p.InternalSource[p.InternalOffset] == '{'
		if braced {
			p.InternalOffset++
		}
		if p.InternalOffset == len(p.InternalSource) ||
			!InternalAdNameStart(p.InternalSource[p.InternalOffset]) {
			return p.InternalFailure(start, "expected a simple variable name", ErrADFilterSyntax)
		}
		begin := p.InternalOffset
		for p.InternalOffset < len(p.InternalSource) && InternalAdNamePart(p.InternalSource[p.InternalOffset]) {
			p.InternalOffset++
		}
		p.InternalToken.InternalKind = 'v'
		p.InternalToken.InternalText = p.InternalSource[begin:p.InternalOffset]
		if braced {
			if p.InternalOffset == len(p.InternalSource) ||
				p.InternalSource[p.InternalOffset] != '}' {
				return p.InternalFailure(
					start,
					"expected simple braced variable",
					ErrADFilterSyntax,
				)
			}
			p.InternalOffset++
		}
		return nil
	}
	if c == '-' && p.InternalOffset < len(p.InternalSource) &&
		InternalAdNameStart(p.InternalSource[p.InternalOffset]) {
		for p.InternalOffset < len(p.InternalSource) && InternalAdNameStart(p.InternalSource[p.InternalOffset]) {
			p.InternalOffset++
		}
		p.InternalToken.InternalKind = 'o'
		p.InternalToken.InternalText = strings.ToLower(p.InternalSource[start:p.InternalOffset])
		return nil
	}
	if InternalAdDigit(c) ||
		(c == '-' || c == '+') && p.InternalOffset < len(p.InternalSource) &&
			InternalAdDigit(p.InternalSource[p.InternalOffset]) {
		for p.InternalOffset < len(p.InternalSource) {
			v := p.InternalSource[p.InternalOffset]
			if !InternalAdNamePart(v) && v != '.' && v != '+' && v != '-' {
				break
			}
			p.InternalOffset++
		}
		p.InternalToken.InternalKind = 'n'
		p.InternalToken.InternalText = p.InternalSource[start:p.InternalOffset]
		return nil
	}
	if InternalAdNameStart(c) {
		for p.InternalOffset < len(p.InternalSource) {
			v := p.InternalSource[p.InternalOffset]
			if !InternalAdNamePart(v) && v != '-' && v != ';' && v != '.' {
				break
			}
			p.InternalOffset++
		}
		p.InternalToken.InternalKind = 'a'
		p.InternalToken.InternalText = p.InternalSource[start:p.InternalOffset]
		return nil
	}
	return p.InternalFailure(start, "unsupported character or executable syntax", ErrADFilterSyntax)
}

func (p *InternalAdExpressionParser) InternalParseOr(depth int) (*InternalAdExpressionNode, error) {
	return p.InternalParseJoin(depth, "-or", p.InternalParseAnd)
}

func (p *InternalAdExpressionParser) InternalParseAnd(
	depth int,
) (*InternalAdExpressionNode, error) {
	return p.InternalParseJoin(depth, "-and", p.InternalParseNot)
}

func (p *InternalAdExpressionParser) InternalParseJoin(
	depth int,
	op string,
	child func(int) (*InternalAdExpressionNode, error),
) (*InternalAdExpressionNode, error) {
	first, err := child(depth)
	if err != nil {
		return nil, err
	}
	children := []*InternalAdExpressionNode{first}
	for p.InternalToken.InternalKind == 'o' && p.InternalToken.InternalText == op {
		if err = p.InternalNext(); err != nil {
			return nil, err
		}
		next, err := child(depth)
		if err != nil {
			return nil, err
		}
		children = append(children, next)
	}
	if len(children) == 1 {
		return first, nil
	}
	return &InternalAdExpressionNode{
		InternalOp:       op,
		InternalChildren: children,
		InternalPos:      first.InternalPos,
	}, nil
}

func (p *InternalAdExpressionParser) InternalParseNot(
	depth int,
) (*InternalAdExpressionNode, error) {
	if depth >= MaxFilterDepth {
		return nil, p.InternalFailure(
			p.InternalToken.InternalPos,
			"expression exceeds nesting limit",
			ErrFilterLimit,
		)
	}
	if p.InternalToken.InternalKind == 'o' && p.InternalToken.InternalText == "-not" {
		pos := p.InternalToken.InternalPos
		if err := p.InternalNext(); err != nil {
			return nil, err
		}
		child, err := p.InternalParseNot(depth + 1)
		if err != nil {
			return nil, err
		}
		return &InternalAdExpressionNode{
			InternalOp:       "-not",
			InternalPos:      pos,
			InternalChildren: []*InternalAdExpressionNode{child},
		}, nil
	}
	if p.InternalToken.InternalKind == '(' {
		if err := p.InternalNext(); err != nil {
			return nil, err
		}
		node, err := p.InternalParseOr(depth + 1)
		if err != nil {
			return nil, err
		}
		if p.InternalToken.InternalKind != ')' {
			return nil, p.InternalFailure(
				p.InternalToken.InternalPos,
				"expected closing parenthesis",
				ErrADFilterSyntax,
			)
		}
		if err = p.InternalNext(); err != nil {
			return nil, err
		}
		return node, nil
	}
	if p.InternalToken.InternalKind != 'a' && p.InternalToken.InternalKind != 'n' {
		return nil, p.InternalFailure(
			p.InternalToken.InternalPos,
			"expected property name",
			ErrADFilterSyntax,
		)
	}
	node := &InternalAdExpressionNode{
		InternalAttribute: p.InternalToken.InternalText,
		InternalPos:       p.InternalToken.InternalPos,
	}
	if !InternalValidFilterAttribute(node.InternalAttribute) {
		return nil, p.InternalFailure(node.InternalPos, "invalid property name", ErrADFilterSyntax)
	}
	if err := p.InternalNext(); err != nil {
		return nil, err
	}
	if p.InternalToken.InternalKind != 'o' ||
		!InternalAdComparisonOperator(p.InternalToken.InternalText) {
		return nil, p.InternalFailure(
			p.InternalToken.InternalPos,
			"expected supported comparison operator",
			ErrADFilterSyntax,
		)
	}
	node.InternalOp = p.InternalToken.InternalText
	if err := p.InternalNext(); err != nil {
		return nil, err
	}
	if p.InternalToken.InternalKind != 's' && p.InternalToken.InternalKind != 'n' &&
		p.InternalToken.InternalKind != 'v' {
		return nil, p.InternalFailure(
			p.InternalToken.InternalPos,
			"expected quoted literal, number or simple variable",
			ErrADFilterSyntax,
		)
	}
	node.InternalValue = p.InternalToken
	if err := p.InternalNext(); err != nil {
		return nil, err
	}
	return node, nil
}

func InternalAdComparisonOperator(op string) bool {
	switch op {
	case "-eq",
		"-ne",
		"-lt",
		"-le",
		"-gt",
		"-ge",
		"-approx",
		"-like",
		"-notlike",
		"-band",
		"-bor",
		"-recursivematch":
		return true
	}
	return false
}

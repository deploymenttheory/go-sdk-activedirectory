package activedirectory

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
	p := adExpressionParser{source: expression}
	if len(expression) > MaxFilterBytes {
		return Filter{}, p.failure(0, "expression exceeds size limit", ErrFilterLimit)
	}
	if !utf8.ValidString(expression) || strings.ContainsRune(expression, 0) {
		return Filter{}, p.failure(0, "expression must be UTF-8 without literal NUL", ErrADFilterSyntax)
	}
	if options.Profile > ADFilterGroup {
		return Filter{}, p.failure(0, "unknown property profile", ErrADFilterProperty)
	}
	if err := p.next(); err != nil {
		return Filter{}, err
	}
	braced := p.token.kind == '{'
	if braced {
		if err := p.next(); err != nil {
			return Filter{}, err
		}
	}
	var node *adExpressionNode
	var err error
	if p.token.kind == '*' {
		node = &adExpressionNode{op: "all", pos: p.token.pos}
		err = p.next()
	} else {
		node, err = p.parseOr(0)
	}
	if err != nil {
		return Filter{}, err
	}
	if braced {
		if p.token.kind != '}' {
			return Filter{}, p.failure(p.token.pos, "expected closing brace", ErrADFilterSyntax)
		}
		if err = p.next(); err != nil {
			return Filter{}, err
		}
	}
	if p.token.kind != 0 {
		return Filter{}, p.failure(p.token.pos, "unexpected token after expression", ErrADFilterSyntax)
	}
	binder, err := newADFilterBinder(&p, options)
	if err != nil {
		return Filter{}, err
	}
	return binder.compile(node)
}

type adExpressionNode struct {
	op, attribute string
	value         adExpressionToken
	children      []*adExpressionNode
	pos           int
}
type adExpressionToken struct {
	kind byte
	text string
	pos  int
}
type adExpressionParser struct {
	source         string
	offset, tokens int
	token          adExpressionToken
}

func (p *adExpressionParser) failure(pos int, reason string, cause error) error {
	line, column := 1, 1
	for _, r := range p.source[:min(pos, len(p.source))] {
		if r == '\n' {
			line++
			column = 1
		} else {
			column++
		}
	}
	return &ADFilterError{Offset: pos, Line: line, Column: column, Reason: reason, Cause: cause}
}
func adNameStart(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' }
func adDigit(c byte) bool     { return c >= '0' && c <= '9' }
func adNamePart(c byte) bool  { return adNameStart(c) || adDigit(c) }

func (p *adExpressionParser) next() error {
	for p.offset < len(p.source) {
		r, size := utf8.DecodeRuneInString(p.source[p.offset:])
		if !unicode.IsSpace(r) {
			break
		}
		p.offset += size
	}
	start := p.offset
	p.token = adExpressionToken{pos: start}
	p.tokens++
	if p.tokens > 8192 {
		return p.failure(start, "expression exceeds token limit", ErrFilterLimit)
	}
	if start == len(p.source) {
		return nil
	}
	c := p.source[p.offset]
	p.offset++
	if strings.ContainsRune("(){}*", rune(c)) {
		p.token.kind = c
		return nil
	}
	if c == '\'' || c == '"' {
		var value strings.Builder
		for p.offset < len(p.source) {
			v := p.source[p.offset]
			p.offset++
			if v == c {
				if c == '\'' && p.offset < len(p.source) && p.source[p.offset] == '\'' {
					value.WriteByte(c)
					p.offset++
					continue
				}
				p.token.kind = 's'
				p.token.text = value.String()
				return nil
			}
			if c == '"' && v == '`' {
				// Only backtick-quote is special in the AD parser. Other
				// backticks remain data; PowerShell interpolation is not run.
				if p.offset < len(p.source) && p.source[p.offset] == '"' {
					v = '"'
					p.offset++
				}
			}
			value.WriteByte(v)
		}
		return p.failure(start, "unterminated quoted value", ErrADFilterSyntax)
	}
	if c == '$' {
		braced := p.offset < len(p.source) && p.source[p.offset] == '{'
		if braced {
			p.offset++
		}
		if p.offset == len(p.source) || !adNameStart(p.source[p.offset]) {
			return p.failure(start, "expected a simple variable name", ErrADFilterSyntax)
		}
		begin := p.offset
		for p.offset < len(p.source) && adNamePart(p.source[p.offset]) {
			p.offset++
		}
		p.token.kind = 'v'
		p.token.text = p.source[begin:p.offset]
		if braced {
			if p.offset == len(p.source) || p.source[p.offset] != '}' {
				return p.failure(start, "expected simple braced variable", ErrADFilterSyntax)
			}
			p.offset++
		}
		return nil
	}
	if c == '-' && p.offset < len(p.source) && adNameStart(p.source[p.offset]) {
		for p.offset < len(p.source) && adNameStart(p.source[p.offset]) {
			p.offset++
		}
		p.token.kind = 'o'
		p.token.text = strings.ToLower(p.source[start:p.offset])
		return nil
	}
	if adDigit(c) || (c == '-' || c == '+') && p.offset < len(p.source) && adDigit(p.source[p.offset]) {
		for p.offset < len(p.source) {
			v := p.source[p.offset]
			if !adNamePart(v) && v != '.' && v != '+' && v != '-' {
				break
			}
			p.offset++
		}
		p.token.kind = 'n'
		p.token.text = p.source[start:p.offset]
		return nil
	}
	if adNameStart(c) {
		for p.offset < len(p.source) {
			v := p.source[p.offset]
			if !adNamePart(v) && v != '-' && v != ';' && v != '.' {
				break
			}
			p.offset++
		}
		p.token.kind = 'a'
		p.token.text = p.source[start:p.offset]
		return nil
	}
	return p.failure(start, "unsupported character or executable syntax", ErrADFilterSyntax)
}

func (p *adExpressionParser) parseOr(depth int) (*adExpressionNode, error) {
	return p.parseJoin(depth, "-or", p.parseAnd)
}
func (p *adExpressionParser) parseAnd(depth int) (*adExpressionNode, error) {
	return p.parseJoin(depth, "-and", p.parseNot)
}
func (p *adExpressionParser) parseJoin(depth int, op string, child func(int) (*adExpressionNode, error)) (*adExpressionNode, error) {
	first, err := child(depth)
	if err != nil {
		return nil, err
	}
	children := []*adExpressionNode{first}
	for p.token.kind == 'o' && p.token.text == op {
		if err = p.next(); err != nil {
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
	return &adExpressionNode{op: op, children: children, pos: first.pos}, nil
}
func (p *adExpressionParser) parseNot(depth int) (*adExpressionNode, error) {
	if depth >= MaxFilterDepth {
		return nil, p.failure(p.token.pos, "expression exceeds nesting limit", ErrFilterLimit)
	}
	if p.token.kind == 'o' && p.token.text == "-not" {
		pos := p.token.pos
		if err := p.next(); err != nil {
			return nil, err
		}
		child, err := p.parseNot(depth + 1)
		if err != nil {
			return nil, err
		}
		return &adExpressionNode{op: "-not", pos: pos, children: []*adExpressionNode{child}}, nil
	}
	if p.token.kind == '(' {
		if err := p.next(); err != nil {
			return nil, err
		}
		node, err := p.parseOr(depth + 1)
		if err != nil {
			return nil, err
		}
		if p.token.kind != ')' {
			return nil, p.failure(p.token.pos, "expected closing parenthesis", ErrADFilterSyntax)
		}
		if err = p.next(); err != nil {
			return nil, err
		}
		return node, nil
	}
	if p.token.kind != 'a' && p.token.kind != 'n' {
		return nil, p.failure(p.token.pos, "expected property name", ErrADFilterSyntax)
	}
	node := &adExpressionNode{attribute: p.token.text, pos: p.token.pos}
	if !validFilterAttribute(node.attribute) {
		return nil, p.failure(node.pos, "invalid property name", ErrADFilterSyntax)
	}
	if err := p.next(); err != nil {
		return nil, err
	}
	if p.token.kind != 'o' || !adComparisonOperator(p.token.text) {
		return nil, p.failure(p.token.pos, "expected supported comparison operator", ErrADFilterSyntax)
	}
	node.op = p.token.text
	if err := p.next(); err != nil {
		return nil, err
	}
	if p.token.kind != 's' && p.token.kind != 'n' && p.token.kind != 'v' {
		return nil, p.failure(p.token.pos, "expected quoted literal, number or simple variable", ErrADFilterSyntax)
	}
	node.value = p.token
	if err := p.next(); err != nil {
		return nil, err
	}
	return node, nil
}
func adComparisonOperator(op string) bool {
	switch op {
	case "-eq", "-ne", "-lt", "-le", "-gt", "-ge", "-approx", "-like", "-notlike", "-band", "-bor", "-recursivematch":
		return true
	}
	return false
}

package activedirectory

import (
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type adFilterBinder struct {
	parser     *adExpressionParser
	options    ADFilterOptions
	variables  map[string]any
	properties map[string]adFilterProperty
	remaining  int
}
type adFilterProperty struct {
	ADFilterProperty
	computed string
	mask     uint64
	invert   bool
}

func newADFilterBinder(p *adExpressionParser, options ADFilterOptions) (*adFilterBinder, error) {
	b := &adFilterBinder{parser: p, options: options, variables: make(map[string]any), properties: adFilterProperties(options.Profile), remaining: MaxFilterBytes}
	for name, value := range options.Variables {
		key := strings.ToLower(name)
		valid := len(name) > 0 && adNameStart(name[0])
		for i := 1; i < len(name); i++ {
			valid = valid && adNamePart(name[i])
		}
		_, duplicate := b.variables[key]
		if !valid || duplicate || key == "true" || key == "false" || key == "null" {
			return nil, p.failure(0, "invalid, duplicate or reserved variable name", ErrADFilterVariable)
		}
		b.variables[key] = value
	}
	seen := make(map[string]bool)
	for name, property := range options.Properties {
		key := strings.ToLower(name)
		if seen[key] || !validFilterAttribute(name) || !validFilterAttribute(property.Attribute) || property.Syntax > ADFilterGeneralizedTime || b.properties[key].computed != "" {
			return nil, p.failure(0, "invalid, duplicate or computed property override", ErrADFilterProperty)
		}
		seen[key] = true
		b.properties[key] = adFilterProperty{ADFilterProperty: property}
	}
	return b, nil
}

func (b *adFilterBinder) compile(node *adExpressionNode) (Filter, error) {
	var filter Filter
	switch node.op {
	case "all":
		filter = FilterPresent("objectClass")
	case "-and", "-or", "-not":
		// Reserve this node's delimiters/operator before compiling children.
		// One shared budget counts the final RFC filter exactly once, including
		// nested groups, and stops expansion before later siblings allocate.
		if err := b.consume(3, node.pos); err != nil {
			return Filter{}, err
		}
		children := make([]Filter, 0, len(node.children))
		for _, child := range node.children {
			f, err := b.compile(child)
			if err != nil {
				return Filter{}, err
			}
			children = append(children, f)
		}
		switch node.op {
		case "-and":
			filter = FilterAnd(children...)
		case "-or":
			filter = FilterOr(children...)
		case "-not":
			filter = FilterNot(children[0])
		}
	default:
		property, known := b.properties[strings.ToLower(node.attribute)]
		if !known {
			property = adFilterProperty{ADFilterProperty: ADFilterProperty{Attribute: node.attribute}}
		}
		if property.computed == "unsupported" {
			return Filter{}, b.parser.failure(node.pos, "property requires directory-dependent or unsupported conversion", ErrADFilterProperty)
		}
		value, quoted, err := b.value(node.value)
		if err != nil {
			return Filter{}, err
		}
		if property.computed != "" {
			filter, err = b.computed(node, property, value)
		} else {
			filter, err = b.comparison(node, property, value, quoted)
		}
		if err != nil {
			return Filter{}, b.parser.failure(node.value.pos, "value or operator is not supported for this property", err)
		}
	}
	if node.op != "-and" && node.op != "-or" && node.op != "-not" {
		if err := b.consume(len(filter.encoded), node.pos); err != nil {
			return Filter{}, err
		}
	}
	if _, err := filter.nativeLDAP(); err != nil {
		return Filter{}, b.parser.failure(node.pos, "filter cannot be safely submitted by the native backend", err)
	}
	return filter, nil
}

func (b *adFilterBinder) consume(size, pos int) error {
	if size > b.remaining {
		return b.parser.failure(pos, "filter exceeds output size limit", ErrFilterLimit)
	}
	b.remaining -= size
	return nil
}

func (b *adFilterBinder) value(token adExpressionToken) (any, bool, error) {
	switch token.kind {
	case 's':
		return token.text, true, nil
	case 'n':
		v, err := adIntegerLiteral(token.text)
		if err != nil {
			return nil, false, b.parser.failure(token.pos, "expected exact integer literal", err)
		}
		return v, false, nil
	case 'v':
		name := strings.ToLower(token.text)
		if name == "true" {
			return true, false, nil
		}
		if name == "false" {
			return false, false, nil
		}
		value, found := b.variables[name]
		if name == "null" || !found || value == nil {
			return nil, false, b.parser.failure(token.pos, "variable is missing or null; use -like/-notlike '*' for presence", ErrADFilterVariable)
		}
		if text, ok := value.(string); ok && !utf8.ValidString(text) {
			return nil, false, b.parser.failure(token.pos, "text variable is not UTF-8; use binary bytes explicitly", ErrADFilterConversion)
		}
		return value, false, nil
	}
	return nil, false, b.parser.failure(token.pos, "unsupported value", ErrADFilterSyntax)
}

// Integers remain exact, including unsigned masks and values above 2^53.
// Fractional/exponent numeric literals are deliberately rejected rather than
// reproducing the reference parser's truncation through floating point.
func adIntegerLiteral(text string) (any, error) {
	base := 10
	unsigned := text
	if strings.HasPrefix(unsigned, "+") || strings.HasPrefix(unsigned, "-") {
		unsigned = unsigned[1:]
	}
	if strings.HasPrefix(strings.ToLower(unsigned), "0x") {
		base = 0
	} else {
		for i := range unsigned {
			if !adDigit(unsigned[i]) {
				return nil, ErrADFilterConversion
			}
		}
	}
	if n, err := strconv.ParseInt(text, base, 64); err == nil {
		return n, nil
	}
	if !strings.HasPrefix(text, "-") {
		if n, err := strconv.ParseUint(strings.TrimPrefix(text, "+"), base, 64); err == nil {
			return n, nil
		}
	}
	return nil, ErrADFilterConversion
}

func (b *adFilterBinder) comparison(node *adExpressionNode, property adFilterProperty, value any, quoted bool) (Filter, error) {
	attribute := property.Attribute
	like := node.op == "-like" || node.op == "-notlike"
	var pattern []adPatternPart
	if text, ok := value.(string); ok {
		var err error
		pattern, err = adDecodePattern(text, quoted, like)
		if err != nil {
			return Filter{}, err
		}
		if !like {
			value = string(pattern[0].value)
			if property.Syntax == ADFilterBinary || property.Syntax == ADFilterScalar && !utf8.Valid(pattern[0].value) {
				value = pattern[0].value
			}
		}
	}
	if like {
		if pattern == nil {
			return Filter{}, ErrADFilterConversion
		}
		filter, presence := adPatternFilter(attribute, pattern)
		if !presence && property.Syntax != ADFilterScalar && property.Syntax != ADFilterString {
			return Filter{}, ErrADFilterConversion
		}
		if node.op == "-notlike" {
			filter = FilterNot(filter)
			if !presence {
				filter = FilterAnd(filter, FilterPresent(attribute))
			}
		}
		return filter, nil
	}
	converted, err := adConvertValue(value, property.Syntax)
	if err != nil {
		return Filter{}, err
	}
	switch node.op {
	case "-eq":
		return FilterEqual(attribute, converted), nil
	case "-ne":
		return FilterAnd(FilterNot(FilterEqual(attribute, converted)), FilterPresent(attribute)), nil
	case "-ge":
		return FilterGreaterOrEqual(attribute, converted), nil
	case "-le":
		return FilterLessOrEqual(attribute, converted), nil
	case "-gt":
		return FilterAnd(FilterNot(FilterLessOrEqual(attribute, converted)), FilterPresent(attribute)), nil
	case "-lt":
		return FilterAnd(FilterNot(FilterGreaterOrEqual(attribute, converted)), FilterPresent(attribute)), nil
	case "-approx":
		return FilterApprox(attribute, converted), nil
	case "-band", "-bor":
		text, err := adScalarText(value)
		if err != nil {
			return Filter{}, err
		}
		mask, err := adIntegerLiteral(text)
		if err != nil {
			return Filter{}, err
		}
		text, err = adScalarText(mask)
		if err != nil {
			return Filter{}, err
		}
		rule := MatchingRuleBitAnd
		if node.op == "-bor" {
			rule = MatchingRuleBitOr
		}
		return FilterExtensible(ExtensibleFilter{Attribute: attribute, Rule: rule, Value: FilterText(text)}), nil
	case "-recursivematch":
		text, ok := value.(string)
		if !ok {
			return Filter{}, ErrADFilterConversion
		}
		return FilterInChain(attribute, text), nil
	}
	return Filter{}, ErrADFilterSyntax
}

type adPatternPart struct {
	value    []byte
	wildcard bool
}

// LDAP hex escapes apply to expression string literals; bound Go strings are
// already values and retain their backslashes. Only unescaped '*' in a -like
// operand creates a wildcard. Hex-escaped stars always remain literal octets.
func adDecodePattern(text string, escaped, wildcard bool) ([]adPatternPart, error) {
	if len(text) > MaxFilterBytes {
		return nil, ErrFilterLimit
	}
	parts := []adPatternPart{{}}
	for i := 0; i < len(text); i++ {
		v := text[i]
		if v == '\\' && escaped {
			if i+2 >= len(text) {
				return nil, ErrADFilterSyntax
			}
			decoded, err := hex.DecodeString(text[i+1 : i+3])
			if err != nil {
				return nil, ErrADFilterSyntax
			}
			parts[len(parts)-1].value = append(parts[len(parts)-1].value, decoded[0])
			i += 2
			continue
		}
		if v == '*' && wildcard {
			if len(parts) == 1 || len(parts[len(parts)-1].value) > 0 {
				parts = append(parts, adPatternPart{wildcard: true}, adPatternPart{})
			}
			continue
		}
		parts[len(parts)-1].value = append(parts[len(parts)-1].value, v)
	}
	return parts, nil
}
func adPartValue(value []byte) FilterValue {
	if utf8.Valid(value) {
		return FilterText(string(value))
	}
	return FilterBytes(value)
}
func adPatternFilter(attribute string, parts []adPatternPart) (Filter, bool) {
	if len(parts) == 1 {
		return FilterEqual(attribute, adPartValue(parts[0].value)), false
	}
	var segments SubstringFilter
	for i, part := range parts {
		if part.wildcard || len(part.value) == 0 {
			continue
		}
		v := adPartValue(part.value)
		switch i {
		case 0:
			segments.Initial = v
		case len(parts) - 1:
			segments.Final = v
		default:
			segments.Any = append(segments.Any, v)
		}
	}
	if !segments.Initial.set && !segments.Final.set && len(segments.Any) == 0 {
		return FilterPresent(attribute), true
	}
	return FilterSubstrings(attribute, segments), false
}

func adConvertValue(value any, syntax ADFilterSyntax) (FilterValue, error) {
	if syntax == ADFilterGUID {
		switch v := value.(type) {
		case string:
			g, e := ParseGUID(v)
			return FilterBytes(g.Bytes()), e
		case GUID:
			return FilterBytes(v.Bytes()), nil
		case []byte:
			g, e := GUIDFromBytes(v)
			return FilterBytes(g.Bytes()), e
		}
		return FilterValue{}, ErrADFilterConversion
	}
	if syntax == ADFilterSID {
		switch v := value.(type) {
		case string:
			s, e := ParseSID(v)
			return FilterBytes(s.Bytes()), e
		case SID:
			_, e := SIDFromBytes(v.Bytes())
			return FilterBytes(v.Bytes()), e
		case []byte:
			s, e := SIDFromBytes(v)
			return FilterBytes(s.Bytes()), e
		}
		return FilterValue{}, ErrADFilterConversion
	}
	if syntax == ADFilterBoolean {
		v, err := adBool(value)
		if err != nil {
			return FilterValue{}, err
		}
		if v {
			return FilterText("TRUE"), nil
		}
		return FilterText("FALSE"), nil
	}
	if syntax == ADFilterFileTime {
		switch v := value.(type) {
		case time.Time:
			stamp, e := FileTimeFromTime(v)
			return FilterText(stamp.LDAPString()), e
		case FileTime:
			return FilterText(v.LDAPString()), nil
		case string:
			stamp, e := ParseFileTime(v)
			return FilterText(stamp.LDAPString()), e
		}
		text, err := adScalarText(value)
		if err != nil {
			return FilterValue{}, err
		}
		stamp, err := ParseFileTime(text)
		return FilterText(stamp.LDAPString()), err
	}
	if syntax == ADFilterGeneralizedTime {
		switch v := value.(type) {
		case time.Time:
			utc := v.UTC()
			if utc.Year() < 1 || utc.Year() > 9999 {
				return FilterValue{}, ErrValueRange
			}
			return FilterText(utc.Format("20060102150405.000000000Z")), nil
		case GeneralizedTime:
			_, e := ParseGeneralizedTime(v.String())
			return FilterText(v.String()), e
		case string:
			g, e := ParseGeneralizedTime(v)
			return FilterText(g.String()), e
		}
		return FilterValue{}, ErrADFilterConversion
	}
	if syntax == ADFilterBinary {
		switch v := value.(type) {
		case []byte:
			return FilterBytes(v), nil
		case GUID:
			return FilterBytes(v.Bytes()), nil
		case SID:
			return FilterBytes(v.Bytes()), nil
		case RawValue:
			return FilterBytes(v.Bytes()), nil
		}
		return FilterValue{}, ErrADFilterConversion
	}
	if syntax == ADFilterInteger {
		text, e := adScalarText(value)
		if e != nil {
			return FilterValue{}, e
		}
		n, e := adIntegerLiteral(text)
		if e != nil {
			return FilterValue{}, e
		}
		text, e = adScalarText(n)
		return FilterText(text), e
	}
	if syntax == ADFilterScalar {
		switch v := value.(type) {
		case []byte:
			return FilterBytes(v), nil
		case GUID:
			return FilterBytes(v.Bytes()), nil
		case SID:
			return FilterBytes(v.Bytes()), nil
		case RawValue:
			return FilterBytes(v.Bytes()), nil
		case FileTime:
			return FilterText(v.LDAPString()), nil
		case GeneralizedTime:
			_, e := ParseGeneralizedTime(v.String())
			return FilterText(v.String()), e
		case Flags32:
			return FilterText(v.LDAPString()), nil
		}
	}
	text, err := adScalarText(value)
	if err != nil {
		return FilterValue{}, err
	}
	return FilterText(text), nil
}
func adScalarText(value any) (string, error) {
	switch v := value.(type) {
	case string:
		if !utf8.ValidString(v) {
			return "", ErrADFilterConversion
		}
		return v, nil
	case bool:
		if v {
			return "TRUE", nil
		}
		return "FALSE", nil
	case int:
		return strconv.FormatInt(int64(v), 10), nil
	case int8:
		return strconv.FormatInt(int64(v), 10), nil
	case int16:
		return strconv.FormatInt(int64(v), 10), nil
	case int32:
		return strconv.FormatInt(int64(v), 10), nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case uint:
		return strconv.FormatUint(uint64(v), 10), nil
	case uint8:
		return strconv.FormatUint(uint64(v), 10), nil
	case uint16:
		return strconv.FormatUint(uint64(v), 10), nil
	case uint32:
		return strconv.FormatUint(uint64(v), 10), nil
	case uint64:
		return strconv.FormatUint(v, 10), nil
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v != math.Trunc(v) || math.Abs(v) > 1<<53 {
			return "", ErrValuePrecision
		}
		return strconv.FormatFloat(v, 'f', 0, 64), nil
	}
	return "", ErrADFilterConversion
}
func adBool(value any) (bool, error) {
	if b, ok := value.(bool); ok {
		return b, nil
	}
	if s, ok := value.(string); ok {
		if strings.EqualFold(s, "true") {
			return true, nil
		}
		if strings.EqualFold(s, "false") {
			return false, nil
		}
	}
	return false, ErrADFilterConversion
}

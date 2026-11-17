package model

import (
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type InternalAdFilterBinder struct {
	InternalParser     *InternalAdExpressionParser
	InternalOptions    ADFilterOptions
	InternalVariables  map[string]any
	InternalProperties map[string]InternalAdFilterProperty
	InternalRemaining  int
}
type InternalAdFilterProperty struct {
	ADFilterProperty
	InternalComputed string
	InternalMask     uint64
	InternalInvert   bool
}

func InternalNewADFilterBinder(
	p *InternalAdExpressionParser,
	options ADFilterOptions,
) (*InternalAdFilterBinder, error) {
	b := &InternalAdFilterBinder{
		InternalParser:     p,
		InternalOptions:    options,
		InternalVariables:  make(map[string]any),
		InternalProperties: InternalAdFilterProperties(options.Profile),
		InternalRemaining:  MaxFilterBytes,
	}
	for name, value := range options.Variables {
		key := strings.ToLower(name)
		valid := len(name) > 0 && InternalAdNameStart(name[0])
		for i := 1; i < len(name); i++ {
			valid = valid && InternalAdNamePart(name[i])
		}
		_, duplicate := b.InternalVariables[key]
		if !valid || duplicate || key == "true" || key == "false" || key == "null" {
			return nil, p.InternalFailure(
				0,
				"invalid, duplicate or reserved variable name",
				ErrADFilterVariable,
			)
		}
		b.InternalVariables[key] = value
	}
	seen := make(map[string]bool)
	for name, property := range options.Properties {
		key := strings.ToLower(name)
		if seen[key] || !InternalValidFilterAttribute(name) ||
			!InternalValidFilterAttribute(property.Attribute) ||
			property.Syntax > ADFilterGeneralizedTime ||
			b.InternalProperties[key].InternalComputed != "" {
			return nil, p.InternalFailure(
				0,
				"invalid, duplicate or computed property override",
				ErrADFilterProperty,
			)
		}
		seen[key] = true
		b.InternalProperties[key] = InternalAdFilterProperty{ADFilterProperty: property}
	}
	return b, nil
}

func (b *InternalAdFilterBinder) InternalCompile(node *InternalAdExpressionNode) (Filter, error) {
	var filter Filter
	switch node.InternalOp {
	case "all":
		filter = FilterPresent("objectClass")
	case "-and", "-or", "-not":
		// Reserve this node's delimiters/operator before compiling children.
		// One shared budget counts the final RFC filter exactly once, including
		// nested groups, and stops expansion before later siblings allocate.
		if err := b.InternalConsume(3, node.InternalPos); err != nil {
			return Filter{}, err
		}
		children := make([]Filter, 0, len(node.InternalChildren))
		for _, child := range node.InternalChildren {
			f, err := b.InternalCompile(child)
			if err != nil {
				return Filter{}, err
			}
			children = append(children, f)
		}
		switch node.InternalOp {
		case "-and":
			filter = FilterAnd(children...)
		case "-or":
			filter = FilterOr(children...)
		case "-not":
			filter = FilterNot(children[0])
		}
	default:
		property, known := b.InternalProperties[strings.ToLower(node.InternalAttribute)]
		if !known {
			property = InternalAdFilterProperty{
				ADFilterProperty: ADFilterProperty{Attribute: node.InternalAttribute},
			}
		}
		if property.InternalComputed == "unsupported" {
			return Filter{}, b.InternalParser.InternalFailure(
				node.InternalPos,
				"property requires directory-dependent or unsupported conversion",
				ErrADFilterProperty,
			)
		}
		value, quoted, err := b.InternalValue(node.InternalValue)
		if err != nil {
			return Filter{}, err
		}
		if property.InternalComputed != "" {
			filter, err = b.InternalComputed(node, property, value)
		} else {
			filter, err = b.InternalComparison(node, property, value, quoted)
		}
		if err != nil {
			return Filter{}, b.InternalParser.InternalFailure(
				node.InternalValue.InternalPos,
				"value or operator is not supported for this property",
				err,
			)
		}
	}
	if node.InternalOp != "-and" && node.InternalOp != "-or" && node.InternalOp != "-not" {
		if err := b.InternalConsume(len(filter.encoded), node.InternalPos); err != nil {
			return Filter{}, err
		}
	}
	if _, err := InternalFilterNativeLDAP(filter); err != nil {
		return Filter{}, b.InternalParser.InternalFailure(
			node.InternalPos,
			"filter cannot be safely submitted by the native backend",
			err,
		)
	}
	return filter, nil
}

func (b *InternalAdFilterBinder) InternalConsume(size, pos int) error {
	if size > b.InternalRemaining {
		return b.InternalParser.InternalFailure(
			pos,
			"filter exceeds output size limit",
			ErrFilterLimit,
		)
	}
	b.InternalRemaining -= size
	return nil
}

func (b *InternalAdFilterBinder) InternalValue(token InternalAdExpressionToken) (any, bool, error) {
	switch token.InternalKind {
	case 's':
		return token.InternalText, true, nil
	case 'n':
		v, err := InternalAdIntegerLiteral(token.InternalText)
		if err != nil {
			return nil, false, b.InternalParser.InternalFailure(
				token.InternalPos,
				"expected exact integer literal",
				err,
			)
		}
		return v, false, nil
	case 'v':
		name := strings.ToLower(token.InternalText)
		if name == "true" {
			return true, false, nil
		}
		if name == "false" {
			return false, false, nil
		}
		value, found := b.InternalVariables[name]
		if name == "null" || !found || value == nil {
			return nil, false, b.InternalParser.InternalFailure(
				token.InternalPos,
				"variable is missing or null; use -like/-notlike '*' for presence",
				ErrADFilterVariable,
			)
		}
		if text, ok := value.(string); ok && !utf8.ValidString(text) {
			return nil, false, b.InternalParser.InternalFailure(
				token.InternalPos,
				"text variable is not UTF-8; use binary bytes explicitly",
				ErrADFilterConversion,
			)
		}
		return value, false, nil
	}
	return nil, false, b.InternalParser.InternalFailure(
		token.InternalPos,
		"unsupported value",
		ErrADFilterSyntax,
	)
}

// Integers remain exact, including unsigned masks and values above 2^53.
// Fractional/exponent numeric literals are deliberately rejected rather than
// reproducing the reference parser's truncation through floating point.
func InternalAdIntegerLiteral(text string) (any, error) {
	base := 10
	unsigned := text
	if strings.HasPrefix(unsigned, "+") || strings.HasPrefix(unsigned, "-") {
		unsigned = unsigned[1:]
	}
	if strings.HasPrefix(strings.ToLower(unsigned), "0x") {
		base = 0
	} else {
		for i := range unsigned {
			if !InternalAdDigit(unsigned[i]) {
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

func (b *InternalAdFilterBinder) InternalComparison(
	node *InternalAdExpressionNode,
	property InternalAdFilterProperty,
	value any,
	quoted bool,
) (Filter, error) {
	attribute := property.Attribute
	like := node.InternalOp == "-like" || node.InternalOp == "-notlike"
	var pattern []InternalAdPatternPart
	if text, ok := value.(string); ok {
		var err error
		pattern, err = InternalAdDecodePattern(text, quoted, like)
		if err != nil {
			return Filter{}, err
		}
		if !like {
			value = string(pattern[0].InternalValue)
			if property.Syntax == ADFilterBinary ||
				property.Syntax == ADFilterScalar && !utf8.Valid(pattern[0].InternalValue) {
				value = pattern[0].InternalValue
			}
		}
	}
	if like {
		if pattern == nil {
			return Filter{}, ErrADFilterConversion
		}
		filter, presence := InternalAdPatternFilter(attribute, pattern)
		if !presence && property.Syntax != ADFilterScalar && property.Syntax != ADFilterString {
			return Filter{}, ErrADFilterConversion
		}
		if node.InternalOp == "-notlike" {
			filter = FilterNot(filter)
			if !presence {
				filter = FilterAnd(filter, FilterPresent(attribute))
			}
		}
		return filter, nil
	}
	converted, err := InternalAdConvertValue(value, property.Syntax)
	if err != nil {
		return Filter{}, err
	}
	switch node.InternalOp {
	case "-eq":
		return FilterEqual(attribute, converted), nil
	case "-ne":
		return FilterAnd(
			FilterNot(FilterEqual(attribute, converted)),
			FilterPresent(attribute),
		), nil
	case "-ge":
		return FilterGreaterOrEqual(attribute, converted), nil
	case "-le":
		return FilterLessOrEqual(attribute, converted), nil
	case "-gt":
		return FilterAnd(
			FilterNot(FilterLessOrEqual(attribute, converted)),
			FilterPresent(attribute),
		), nil
	case "-lt":
		return FilterAnd(
			FilterNot(FilterGreaterOrEqual(attribute, converted)),
			FilterPresent(attribute),
		), nil
	case "-approx":
		return FilterApprox(attribute, converted), nil
	case "-band", "-bor":
		text, err := InternalAdScalarText(value)
		if err != nil {
			return Filter{}, err
		}
		mask, err := InternalAdIntegerLiteral(text)
		if err != nil {
			return Filter{}, err
		}
		text, err = InternalAdScalarText(mask)
		if err != nil {
			return Filter{}, err
		}
		rule := MatchingRuleBitAnd
		if node.InternalOp == "-bor" {
			rule = MatchingRuleBitOr
		}
		return FilterExtensible(
			ExtensibleFilter{Attribute: attribute, Rule: rule, Value: FilterText(text)},
		), nil
	case "-recursivematch":
		text, ok := value.(string)
		if !ok {
			return Filter{}, ErrADFilterConversion
		}
		return FilterInChain(attribute, text), nil
	}
	return Filter{}, ErrADFilterSyntax
}

type InternalAdPatternPart struct {
	InternalValue    []byte
	InternalWildcard bool
}

// LDAP hex escapes apply to expression string literals; bound Go strings are
// already values and retain their backslashes. Only unescaped '*' in a -like
// operand creates a wildcard. Hex-escaped stars always remain literal octets.
func InternalAdDecodePattern(text string, escaped, wildcard bool) ([]InternalAdPatternPart, error) {
	if len(text) > MaxFilterBytes {
		return nil, ErrFilterLimit
	}
	parts := []InternalAdPatternPart{{}}
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
			parts[len(parts)-1].InternalValue = append(
				parts[len(parts)-1].InternalValue,
				decoded[0],
			)
			i += 2
			continue
		}
		if v == '*' && wildcard {
			if len(parts) == 1 || len(parts[len(parts)-1].InternalValue) > 0 {
				parts = append(
					parts,
					InternalAdPatternPart{InternalWildcard: true},
					InternalAdPatternPart{},
				)
			}
			continue
		}
		parts[len(parts)-1].InternalValue = append(parts[len(parts)-1].InternalValue, v)
	}
	return parts, nil
}

func InternalAdPartValue(value []byte) FilterValue {
	if utf8.Valid(value) {
		return FilterText(string(value))
	}
	return FilterBytes(value)
}

func InternalAdPatternFilter(attribute string, parts []InternalAdPatternPart) (Filter, bool) {
	if len(parts) == 1 {
		return FilterEqual(attribute, InternalAdPartValue(parts[0].InternalValue)), false
	}
	var segments SubstringFilter
	for i, part := range parts {
		if part.InternalWildcard || len(part.InternalValue) == 0 {
			continue
		}
		v := InternalAdPartValue(part.InternalValue)
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

func InternalAdConvertValue(value any, syntax ADFilterSyntax) (FilterValue, error) {
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
		v, err := InternalAdBool(value)
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
		text, err := InternalAdScalarText(value)
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
		text, e := InternalAdScalarText(value)
		if e != nil {
			return FilterValue{}, e
		}
		n, e := InternalAdIntegerLiteral(text)
		if e != nil {
			return FilterValue{}, e
		}
		text, e = InternalAdScalarText(n)
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
	text, err := InternalAdScalarText(value)
	if err != nil {
		return FilterValue{}, err
	}
	return FilterText(text), nil
}

func InternalAdScalarText(value any) (string, error) {
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

func InternalAdBool(value any) (bool, error) {
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

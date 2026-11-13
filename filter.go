package activedirectory

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	ErrInvalidFilter          = errors.New("invalid typed LDAP filter")
	ErrFilterLimit            = errors.New("typed LDAP filter exceeds construction limit")
	ErrConflictingFilters     = errors.New("raw and typed LDAP filters are mutually exclusive")
	ErrUnsupportedFilterValue = errors.New("native LDAP backend cannot safely encode this extensible assertion value")
	ErrInvalidDNValue         = errors.New("distinguished name attribute value must be valid UTF-8")
)

// Typed filter construction is bounded; exceeding either limit returns an
// error, never a truncated query. Existing raw SearchOptions.Filter is unchanged.
const (
	MaxFilterBytes = 1 << 20
	MaxFilterDepth = 64
)

// Filter is an immutable, safely composed RFC 4515 expression. Constructors
// retain validation errors; LDAP or SearchOptions.Validate reports them before
// native execution. Values can never introduce filter syntax. A zero Filter is
// unset in SearchOptions and invalid when composed or encoded on its own.
type Filter struct {
	encoded string
	depth   int
	err     error
	// WinLDAP's extensible-match parser copies assertion text literally,
	// unlike its ordinary RFC 4515 assertion parser. Keep that representation
	// separate from portable LDAP output; never reinterpret legacy raw filters.
	native    string
	nativeErr error
}

// LDAP returns the complete LDAP filter string, or the construction error.
// It does not validate server schema, matching-rule support, or permissions.
func (f Filter) LDAP() (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if f.encoded == "" {
		return "", ErrInvalidFilter
	}
	return f.encoded, nil
}

func (f Filter) unset() bool { return f.encoded == "" && f.err == nil }

func (f Filter) nativeLDAP() (string, error) {
	encoded, err := f.LDAP()
	if err != nil {
		return "", err
	}
	if f.nativeErr != nil {
		return "", f.nativeErr
	}
	if f.native != "" {
		return f.native, nil
	}
	return encoded, nil
}

// FilterValue holds assertion octets, not executable LDAP or DN syntax.
// Its zero value is invalid, except as an omitted Initial/Final substring.
type FilterValue struct {
	value  string
	binary bool
	set    bool
}

// FilterText selects literal UTF-8 text. NUL and filter metacharacters are
// escaped, including '*' (which never becomes a wildcard). Invalid UTF-8 is
// rejected when the value is composed; use FilterBytes for arbitrary octets.
func FilterText(value string) FilterValue { return FilterValue{value: value, set: true} }

// FilterBytes copies arbitrary assertion octets, including GUID/SID encodings.
// Every octet is hexadecimal-escaped. Nil/empty bytes are valid empty values.
// GUIDs use LDAP's Windows GUID byte order; SIDs use their binary SID layout.
func FilterBytes(value []byte) FilterValue {
	return FilterValue{value: string(value), binary: true, set: true}
}

// FilterInteger encodes an exact signed decimal integer without float conversion.
func FilterInteger(value int64) FilterValue { return FilterText(strconv.FormatInt(value, 10)) }

func (v FilterValue) escaped() (string, error) {
	if !v.set || (!v.binary && !utf8.ValidString(v.value)) {
		return "", ErrInvalidFilter
	}
	if len(v.value) > MaxFilterBytes {
		return "", ErrFilterLimit
	}
	if !v.binary {
		// Reuse the same literal escaping as directory and identity searches.
		value := ldapLiteral(v.value)
		if len(value) > MaxFilterBytes {
			return "", ErrFilterLimit
		}
		return value, nil
	}
	if len(v.value) > MaxFilterBytes/3 {
		return "", ErrFilterLimit
	}
	var out strings.Builder
	out.Grow(len(v.value) * 3)
	const hex = "0123456789abcdef"
	for i := 0; i < len(v.value); i++ {
		b := v.value[i]
		out.WriteByte('\\')
		out.WriteByte(hex[b>>4])
		out.WriteByte(hex[b&15])
	}
	return out.String(), nil
}

func FilterEqual(attribute string, value FilterValue) Filter {
	return filterAssertion(attribute, "=", value)
}
func FilterGreaterOrEqual(attribute string, value FilterValue) Filter {
	return filterAssertion(attribute, ">=", value)
}
func FilterLessOrEqual(attribute string, value FilterValue) Filter {
	return filterAssertion(attribute, "<=", value)
}

// FilterApprox encodes LDAP's ~= operator. Approximate matching semantics are
// server/schema-defined; this constructor does not implement fuzzy matching.
func FilterApprox(attribute string, value FilterValue) Filter {
	return filterAssertion(attribute, "~=", value)
}

func filterAssertion(attribute, operator string, value FilterValue) Filter {
	if !validFilterAttribute(attribute) {
		return Filter{err: ErrInvalidFilter}
	}
	escaped, err := value.escaped()
	if err != nil {
		return Filter{err: err}
	}
	return boundedFilter("("+attribute+operator+escaped+")", 1)
}

func FilterPresent(attribute string) Filter {
	if !validFilterAttribute(attribute) {
		return Filter{err: ErrInvalidFilter}
	}
	return boundedFilter("("+attribute+"=*)", 1)
}

// FilterAnd/FilterOr require at least one nonzero child; empty conjunctions
// are not silently replaced with match-all or match-none searches.
func FilterAnd(filters ...Filter) Filter { return filterBoolean('&', filters) }
func FilterOr(filters ...Filter) Filter  { return filterBoolean('|', filters) }
func FilterNot(filter Filter) Filter     { return filterBoolean('!', []Filter{filter}) }

func filterBoolean(operator byte, filters []Filter) Filter {
	if len(filters) == 0 {
		return Filter{err: ErrInvalidFilter}
	}
	size, depth := 3, 1
	for _, filter := range filters {
		if _, err := filter.LDAP(); err != nil {
			return Filter{err: err}
		}
		if len(filter.encoded) > MaxFilterBytes-size {
			return Filter{err: ErrFilterLimit}
		}
		size += len(filter.encoded)
		depth = max(depth, filter.depth+1)
	}
	if depth > MaxFilterDepth {
		return Filter{err: ErrFilterLimit}
	}
	var out strings.Builder
	var native strings.Builder
	var nativeErr error
	out.Grow(size)
	out.WriteByte('(')
	out.WriteByte(operator)
	native.Grow(size)
	native.WriteByte('(')
	native.WriteByte(operator)
	for _, filter := range filters {
		out.WriteString(filter.encoded)
		value, err := filter.nativeLDAP()
		if err != nil {
			if nativeErr == nil {
				nativeErr = err
			}
		} else {
			native.WriteString(value)
		}
	}
	out.WriteByte(')')
	native.WriteByte(')')
	return Filter{encoded: out.String(), native: native.String(), nativeErr: nativeErr, depth: depth}
}

// SubstringFilter specifies literal segments separated by wildcards. A zero
// Initial or Final omits that anchor. Any segments remain in caller order.
// At least one segment is required and each supplied segment must be nonempty.
// Use FilterPresent for a lone wildcard, FilterEqual for a literal '*'.
type SubstringFilter struct {
	Initial FilterValue
	Any     []FilterValue
	Final   FilterValue
}

func FilterSubstrings(attribute string, parts SubstringFilter) Filter {
	if !validFilterAttribute(attribute) {
		return Filter{err: ErrInvalidFilter}
	}
	if !parts.Initial.set && !parts.Final.set && len(parts.Any) == 0 {
		return Filter{err: ErrInvalidFilter}
	}
	var out strings.Builder
	out.WriteByte('(')
	out.WriteString(attribute)
	out.WriteByte('=')
	appendSegment := func(value FilterValue) error {
		if !value.set || len(value.value) == 0 {
			return ErrInvalidFilter
		}
		encoded, err := value.escaped()
		if err != nil {
			return err
		}
		if len(encoded) > MaxFilterBytes-out.Len()-2 {
			return ErrFilterLimit
		}
		out.WriteString(encoded)
		return nil
	}
	if parts.Initial.set {
		if err := appendSegment(parts.Initial); err != nil {
			return Filter{err: err}
		}
	}
	out.WriteByte('*')
	for _, part := range parts.Any {
		if err := appendSegment(part); err != nil {
			return Filter{err: err}
		}
		out.WriteByte('*')
	}
	if parts.Final.set {
		if err := appendSegment(parts.Final); err != nil {
			return Filter{err: err}
		}
	}
	out.WriteByte(')')
	return boundedFilter(out.String(), 1)
}

// MatchingRule identifies a numeric OID. Custom OIDs are syntax-checked, not
// advertised as supported. AD exposes no matching-rule capability list.
type MatchingRule string

const (
	MatchingRuleBitAnd     MatchingRule = "1.2.840.113556.1.4.803"
	MatchingRuleBitOr      MatchingRule = "1.2.840.113556.1.4.804"
	MatchingRuleInChain    MatchingRule = "1.2.840.113556.1.4.1941"
	MatchingRuleDNWithData MatchingRule = "1.2.840.113556.1.4.2253"
)

// ExtensibleFilter follows RFC 4515. Attribute may be omitted only when Rule
// is specified; Rule may be omitted only when Attribute is specified.
// DNAttributes includes DN attributes in matching when the server supports it.
// AD rule/schema prerequisites and access restrictions remain server-enforced.
type ExtensibleFilter struct {
	Attribute    string
	Rule         MatchingRule
	DNAttributes bool
	Value        FilterValue
}

func FilterExtensible(match ExtensibleFilter) Filter {
	if match.Attribute == "" && match.Rule == "" {
		return Filter{err: ErrInvalidFilter}
	}
	if match.Attribute != "" && !validFilterAttribute(match.Attribute) {
		return Filter{err: ErrInvalidFilter}
	}
	if match.Rule != "" && (len(match.Rule) > MaxFilterBytes || !filterOID.MatchString(string(match.Rule))) {
		return Filter{err: ErrInvalidFilter}
	}
	value, err := match.Value.escaped()
	if err != nil {
		return Filter{err: err}
	}
	prefix := "(" + match.Attribute
	if match.DNAttributes {
		prefix += ":dn"
	}
	if match.Rule != "" {
		prefix += ":" + string(match.Rule)
	}
	filter := boundedFilter(prefix+":="+value+")", 1)
	// Native W-string submission cannot carry NUL/non-UTF8 octets, and raw
	// parentheses can terminate or restructure the native parser's expression.
	// A terminal backslash can escape the closing delimiter in that parser.
	// No assertion bytes are silently changed to work around that limitation.
	if !utf8.ValidString(match.Value.value) || strings.ContainsAny(match.Value.value, "\x00()") || strings.HasSuffix(match.Value.value, `\`) {
		filter.nativeErr = ErrUnsupportedFilterValue
	} else {
		filter.native = prefix + ":=" + match.Value.value + ")"
	}
	return filter
}

// FilterBitAnd matches when every mask bit is set; FilterBitOr matches when
// any mask bit is set. The integer attribute's supported width is schema-defined.
func FilterBitAnd(attribute string, mask uint64) Filter {
	return FilterExtensible(ExtensibleFilter{Attribute: attribute, Rule: MatchingRuleBitAnd, Value: FilterText(strconv.FormatUint(mask, 10))})
}
func FilterBitOr(attribute string, mask uint64) Filter {
	return FilterExtensible(ExtensibleFilter{Attribute: attribute, Rule: MatchingRuleBitOr, Value: FilterText(strconv.FormatUint(mask, 10))})
}

// FilterInChain traverses an AD link attribute (for example member/memberOf).
// dn is an already formed DN, then escaped as a filter assertion value. This
// does not DN-escape the complete DN or alter its components.
func FilterInChain(attribute, dn string) Filter {
	return FilterExtensible(ExtensibleFilter{Attribute: attribute, Rule: MatchingRuleInChain, Value: FilterText(dn)})
}

var filterOID = regexp.MustCompile(`^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))+$`)

func validFilterAttribute(attribute string) bool {
	if len(attribute) > MaxFilterBytes || !attributeDescription.MatchString(attribute) {
		return false
	}
	base, _, _ := strings.Cut(attribute, ";")
	if base[0] >= '0' && base[0] <= '9' {
		return filterOID.MatchString(base)
	}
	return true
}

func boundedFilter(value string, depth int) Filter {
	if len(value) > MaxFilterBytes || depth > MaxFilterDepth {
		return Filter{err: ErrFilterLimit}
	}
	return Filter{encoded: value, depth: depth}
}

// EscapeDNValue escapes one textual RDN attribute value under RFC 4514. It is
// deliberately separate from filter escaping: do not pass a whole DN here.
// When using a formed DN in a filter, pass it through FilterText afterward.
func EscapeDNValue(value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", ErrInvalidDNValue
	}
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		b := value[i]
		switch {
		case b == 0:
			out.WriteString(`\00`)
		case strings.ContainsRune(",+\"\\<>;=", rune(b)), b == ' ' && (i == 0 || i == len(value)-1), b == '#' && i == 0:
			out.WriteByte('\\')
			out.WriteByte(b)
		default:
			out.WriteByte(b)
		}
	}
	return out.String(), nil
}

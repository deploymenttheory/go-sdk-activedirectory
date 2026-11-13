package activedirectory

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
)

var (
	ErrInvalidValue         = errors.New("invalid directory value")
	ErrValuePrecision       = errors.New("directory value cannot be represented without losing precision")
	ErrValueRange           = errors.New("directory value exceeds the requested Go type")
	ErrValueSentinel        = errors.New("directory sentinel requires attribute-specific interpretation")
	ErrAttributeUnavailable = errors.New("attribute is not present and complete")
)

// RawValue owns one LDAP value. Conversions are explicit, never inferred from
// an attribute name. Bytes returns a copy, including unknown binary syntaxes.
type RawValue struct{ data []byte }

func NewRawValue(value []byte) RawValue { return RawValue{data: slices.Clone(value)} }
func (v RawValue) Bytes() []byte        { return slices.Clone(v.data) }
func (v RawValue) Text() (string, error) {
	if !validDirectoryText(string(v.data)) {
		return "", ErrInvalidValue
	}
	return string(v.data), nil
}
func (v RawValue) Bool() (bool, error) {
	value, err := parseLDAPBool(string(v.data))
	if err != nil {
		return false, ErrInvalidValue
	}
	return value, nil
}
func (v RawValue) Int64() (int64, error) {
	value, err := strconv.ParseInt(string(v.data), 10, 64)
	if err != nil {
		return 0, ErrInvalidValue
	}
	return value, nil
}
func (v RawValue) Flags32() (Flags32, error) {
	value, err := parseDirectoryMask(string(v.data))
	if err != nil {
		return 0, ErrInvalidValue
	}
	return Flags32(value), nil
}
func (v RawValue) GUID() (GUID, error)         { return GUIDFromBytes(v.data) }
func (v RawValue) SID() (SID, error)           { return SIDFromBytes(v.data) }
func (v RawValue) FileTime() (FileTime, error) { return ParseFileTime(string(v.data)) }
func (v RawValue) GeneralizedTime() (GeneralizedTime, error) {
	return ParseGeneralizedTime(string(v.data))
}
func (v RawValue) Interval() (Interval100ns, error) {
	value, err := v.Int64()
	return Interval100ns(value), err
}

// AttributeValues retains retrieval state and every value in its original
// order, including duplicates. Ranges are retained separately; no incomplete
// range is silently presented as a complete multi-value attribute.
type AttributeValues struct {
	State  AttributeState
	Values []RawValue
	Ranges map[string][]RawValue
}

func (o Object) Values(name string) AttributeValues {
	values, state := o.Attribute(name)
	result := AttributeValues{State: state, Values: rawValues(values)}
	for returned, rangeValues := range o.Attributes {
		if strings.HasPrefix(returned, strings.ToLower(name)+";range=") {
			if result.Ranges == nil {
				result.Ranges = make(map[string][]RawValue)
			}
			result.Ranges[returned] = rawValues(rangeValues)
			result.State = AttributePartial
		}
	}
	return result
}

func rawValues(values [][]byte) []RawValue {
	if values == nil {
		return nil
	}
	result := make([]RawValue, len(values))
	for i, value := range values {
		result[i] = NewRawValue(value)
	}
	return result
}

// Single refuses missing, unloaded, ranged, empty-set and multi-value input.
// A returned single empty value remains a valid RawValue.
func (v AttributeValues) Single() (RawValue, error) {
	if v.State != AttributePresent {
		return RawValue{}, ErrAttributeUnavailable
	}
	if len(v.Values) != 1 {
		return RawValue{}, ErrInvalidValue
	}
	return v.Values[0], nil
}

// Flags32 preserves all bits, including unknown bits and signed LDAP Integer
// representations such as groupType. LDAPString emits signed 32-bit decimal.
type Flags32 uint32

func (f Flags32) Has(mask Flags32) bool { return f&mask == mask }
func (f Flags32) With(mask Flags32, enabled bool) Flags32 {
	if enabled {
		return f | mask
	}
	return f &^ mask
}
func (f Flags32) LDAPString() string { return strconv.FormatInt(int64(int32(f)), 10) }

// GUID stores exactly the 16 AD/Windows binary bytes: the first three fields
// are little-endian, and the final eight bytes retain their order.
type GUID [16]byte

func GUIDFromBytes(value []byte) (GUID, error) {
	if len(value) != 16 {
		return GUID{}, ErrInvalidValue
	}
	return GUID(value), nil
}
func ParseGUID(value string) (GUID, error) {
	if len(value) == 38 && value[0] == '{' && value[37] == '}' {
		value = value[1:37]
	}
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return GUID{}, ErrInvalidValue
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(decoded) != 16 {
		return GUID{}, ErrInvalidValue
	}
	reverseGUIDFields(decoded)
	return GUID(decoded), nil
}
func reverseGUIDFields(value []byte) {
	value[0], value[1], value[2], value[3] = value[3], value[2], value[1], value[0]
	value[4], value[5] = value[5], value[4]
	value[6], value[7] = value[7], value[6]
}
func (g GUID) Bytes() []byte { return slices.Clone(g[:]) }
func (g GUID) String() string {
	value := g.Bytes()
	reverseGUIDFields(value)
	text := hex.EncodeToString(value)
	return text[:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:]
}

// SID is an immutable revision-1 Windows SID, including arbitrary 48-bit
// identifier authorities and up to 15 subauthorities. Its zero value is invalid.
type SID struct{ encoded string }

func SIDFromBytes(value []byte) (SID, error) {
	if len(value) < 8 || value[0] != 1 || value[1] > 15 || len(value) != 8+4*int(value[1]) {
		return SID{}, ErrInvalidValue
	}
	return SID{encoded: string(value)}, nil
}
func ParseSID(value string) (SID, error) {
	parts := strings.Split(value, "-")
	if len(parts) < 3 || len(parts) > 18 || parts[0] != "S" || parts[1] != "1" {
		return SID{}, ErrInvalidValue
	}
	base, authorityText := 10, parts[2]
	if strings.HasPrefix(authorityText, "0x") {
		base, authorityText = 16, authorityText[2:]
	}
	authority, err := strconv.ParseUint(authorityText, base, 48)
	if err != nil || strings.HasPrefix(authorityText, "+") {
		return SID{}, ErrInvalidValue
	}
	valueBytes := make([]byte, 8+4*(len(parts)-3))
	valueBytes[0], valueBytes[1] = 1, byte(len(parts)-3)
	for i := 0; i < 6; i++ {
		valueBytes[7-i] = byte(authority >> (8 * i))
	}
	for i, part := range parts[3:] {
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil || strings.HasPrefix(part, "+") {
			return SID{}, ErrInvalidValue
		}
		binary.LittleEndian.PutUint32(valueBytes[8+4*i:], uint32(n))
	}
	return SID{encoded: string(valueBytes)}, nil
}
func (s SID) Bytes() []byte { return []byte(s.encoded) }
func (s SID) String() string {
	if len(s.encoded) == 0 {
		return ""
	}
	value := s.Bytes()
	var authority uint64
	for _, octet := range value[2:8] {
		authority = authority<<8 | uint64(octet)
	}
	text := "S-1-" + strconv.FormatUint(authority, 10)
	if authority > math.MaxUint32 {
		text = fmt.Sprintf("S-1-0x%012x", authority)
	}
	for i := 8; i < len(value); i += 4 {
		text += "-" + strconv.FormatUint(uint64(binary.LittleEndian.Uint32(value[i:])), 10)
	}
	return text
}

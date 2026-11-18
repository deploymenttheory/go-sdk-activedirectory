package conditions

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

var resourceTypeTokens = map[string]uint16{"TI": 1, "TU": 2, "TS": 3, "TD": 5, "TB": 6, "TX": 16}

func parseResourceClaim(text string, options SDDLOptions) ([]byte, error) {
	if len(text) < 2 || text[0] != '(' || text[len(text)-1] != ')' {
		return nil, fmt.Errorf("%w: resource claim parentheses", ErrInvalidExpression)
	}
	var fields []string
	start, quoted := 1, false
	for i := 1; i < len(text)-1; i++ {
		if text[i] == '"' {
			quoted = !quoted
		}
		if text[i] == ',' && !quoted {
			fields = append(fields, strings.TrimSpace(text[start:i]))
			start = i + 1
		}
	}
	fields = append(fields, strings.TrimSpace(text[start:len(text)-1]))
	if quoted || len(fields) < 3 || len(fields) > 4099 {
		return nil, fmt.Errorf("%w: resource claim fields", ErrInvalidExpression)
	}
	name, err := quotedResourceString(fields[0])
	if err != nil {
		return nil, err
	}
	// Claim names use the same escaped attribute-name grammar as prefixed
	// conditional operands. Decode their UTF-16 names rather than Go escapes.
	nameParser := conditionParser{text: "@Resource." + name}
	nameNode, err := nameParser.attribute()
	if err != nil || nameParser.at != len(nameParser.text) {
		return nil, fmt.Errorf("%w: resource claim name", ErrInvalidExpression)
	}
	nameBytes := slices.Clone(nameNode.wire[5:])
	nameBytes = append(nameBytes, 0, 0)
	kind, ok := resourceTypeTokens[fields[1]]
	if !ok {
		return nil, fmt.Errorf("%w: resource claim type", ErrInvalidExpression)
	}
	flags, err := parseResourceUnsigned(fields[2])
	if err != nil || flags > 0xffffffff || flags&0xffc0 != 0 {
		return nil, fmt.Errorf("%w: resource claim flags", ErrInvalidExpression)
	}
	count := len(fields) - 3
	if count < 0 || count > 4096 {
		return nil, fmt.Errorf("%w: resource claim count", ErrInvalidExpression)
	}
	result := make([]byte, 16+4*count)
	nameOffset := len(result)
	if nameOffset < 16 || nameOffset > 65535 {
		return nil, fmt.Errorf("%w: resource name offset", ErrInvalidExpression)
	}
	binary.LittleEndian.PutUint32(result[:4], uint32(nameOffset))
	binary.LittleEndian.PutUint16(result[4:6], kind)
	binary.LittleEndian.PutUint32(result[8:12], uint32(flags))
	binary.LittleEndian.PutUint32(result[12:16], uint32(count))
	result = append(result, nameBytes...)
	for i, field := range fields[3:] {
		value, valueErr := encodeResourceValue(kind, field, options)
		if valueErr != nil {
			return nil, valueErr
		}
		offset := len(result)
		if offset < 16 || offset > 65535 || len(value) > 65535-offset {
			return nil, fmt.Errorf("%w: resource value offset", ErrInvalidExpression)
		}
		binary.LittleEndian.PutUint32(result[16+4*i:20+4*i], uint32(offset))
		result = append(result, value...)
	}
	for len(result)%4 != 0 {
		result = append(result, 0)
	}
	return result, nil
}

func quotedResourceString(text string) (string, error) {
	if len(text) < 2 || text[0] != '"' || text[len(text)-1] != '"' || strings.ContainsRune(text[1:len(text)-1], '"') {
		return "", fmt.Errorf("%w: resource quoted string", ErrInvalidExpression)
	}
	return text[1 : len(text)-1], nil
}

func parseResourceUnsigned(text string) (uint64, error) {
	base := 10
	if len(text) != 0 && text[0] == '0' {
		base = 0
	}
	value, err := strconv.ParseUint(text, base, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: unsigned resource value: %w", ErrInvalidExpression, err)
	}
	return value, nil
}

func encodeResourceValue(kind uint16, text string, options SDDLOptions) ([]byte, error) {
	switch kind {
	case 1:
		base := 10
		digits := strings.TrimPrefix(strings.TrimPrefix(text, "-"), "+")
		if strings.HasPrefix(digits, "0") {
			base = 0
		}
		value, err := strconv.ParseInt(text, base, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: signed resource value: %w", ErrInvalidExpression, err)
		}
		// Preserve the specified two's-complement wire representation.
		return binary.LittleEndian.AppendUint64(nil, uint64(value)), nil // #nosec G115 -- signed-to-unsigned bit representation is required by MS-DTYP.
	case 2, 6:
		value, err := parseResourceUnsigned(text)
		if err != nil {
			return nil, err
		}
		if kind == 6 && value > 1 {
			return nil, fmt.Errorf("%w: boolean resource value", ErrInvalidExpression)
		}
		return binary.LittleEndian.AppendUint64(nil, value), nil
	case 3:
		value, err := quotedResourceString(text)
		if err != nil {
			return nil, err
		}
		return encodeUTF16(value, true), nil
	case 5, 16:
		var value []byte
		var err error
		if kind == 5 {
			value, err = parseSDDLSID(text, options)
		} else {
			value, err = hex.DecodeString(strings.TrimPrefix(text, "#"))
		}
		if err != nil {
			return nil, fmt.Errorf("%w: resource octet/SID value: %w", ErrInvalidExpression, err)
		}
		length := len(value)
		if length < 0 || length > 65535 {
			return nil, fmt.Errorf("%w: resource octet size", ErrInvalidExpression)
		}
		return append(binary.LittleEndian.AppendUint32(nil, uint32(length)), value...), nil
	default:
		return nil, fmt.Errorf("%w: resource value type", ErrInvalidExpression)
	}
}

package conditions

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
)

var aceTypeTokens = map[string]byte{
	"A": 0, "D": 1, "AU": 2, "AL": 3, "OA": 5, "OD": 6, "OU": 7, "OL": 8,
	"XA": 9, "XD": 10, "ZA": 11, "ZD": 12, "XU": 13, "XL": 14, "ZU": 15, "ZL": 16,
	"ML": 17, "RA": 18, "SP": 19, "TL": 20, "FL": 21,
}

var aceFlagTokens = map[string]uint32{"OI": 1, "CI": 2, "NP": 4, "IO": 8, "ID": 16, "TP": 32, "SA": 64, "FA": 128}

var aceRightTokens = map[string]uint32{
	"CC": 1, "DC": 2, "LC": 4, "SW": 8, "RP": 16, "WP": 32, "DT": 64, "LO": 128, "CR": 256,
	"SD": 0x10000, "RC": 0x20000, "WD": 0x40000, "WO": 0x80000,
	"GA": 0x10000000, "GX": 0x20000000, "GW": 0x40000000, "GR": 0x80000000,
	"FA": 0x1f01ff, "FX": 0x1200a0, "FW": 0x120116, "FR": 0x120089,
	"KA": 0xf003f, "KR": 0x20019, "KX": 0x20019, "KW": 0x20006,
	"NW": 1, "NR": 2, "NX": 4, "AS": 0x1000000, "MA": 0x2000000,
}

func parseTokenBits(text string, tokens map[string]uint32) (uint32, error) {
	var value uint32
	for len(text) != 0 {
		if len(text) < 2 {
			return 0, fmt.Errorf("%w: truncated SDDL token", ErrInvalidExpression)
		}
		bit, ok := tokens[text[:2]]
		if !ok {
			return 0, fmt.Errorf("%w: unknown SDDL token %q", ErrInvalidExpression, text[:2])
		}
		value |= bit
		text = text[2:]
	}
	return value, nil
}

func parseRights(text string) (uint32, error) {
	if len(text) != 0 && text[0] >= '0' && text[0] <= '9' {
		base := 10
		if text[0] == '0' {
			base = 0
		}
		value, err := strconv.ParseUint(text, base, 32)
		if err != nil {
			return 0, fmt.Errorf("%w: access mask: %w", ErrInvalidExpression, err)
		}
		return uint32(value), nil
	}
	return parseTokenBits(text, aceRightTokens)
}

func parseGUID(text string) ([]byte, error) {
	if len(text) != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-' {
		return nil, fmt.Errorf("%w: GUID syntax", ErrInvalidExpression)
	}
	result, err := hex.DecodeString(strings.ReplaceAll(text, "-", ""))
	if err != nil {
		return nil, fmt.Errorf("%w: GUID: %w", ErrInvalidExpression, err)
	}
	result[0], result[3] = result[3], result[0]
	result[1], result[2] = result[2], result[1]
	result[4], result[5] = result[5], result[4]
	result[6], result[7] = result[7], result[6]
	return result, nil
}

func parseSDDLACE(text string, kind byte, options SDDLOptions) ([]byte, error) {
	fields := strings.SplitN(text, ";", 7)
	if len(fields) < 6 {
		return nil, fmt.Errorf("%w: ACE field count", ErrInvalidExpression)
	}
	typeID, known := aceTypeTokens[fields[0]]
	if !known {
		return nil, fmt.Errorf("%w: unknown ACE type", ErrInvalidExpression)
	}
	system := typeID == 2 || typeID == 3 || typeID == 7 || typeID == 8 || typeID >= 13
	if (kind == 'S') != system {
		return nil, fmt.Errorf("%w: ACE in wrong ACL", ErrInvalidExpression)
	}
	flags, err := parseTokenBits(fields[1], aceFlagTokens)
	if err != nil {
		return nil, err
	}
	if flags > 255 {
		return nil, fmt.Errorf("%w: ACE flag bounds", ErrInvalidExpression)
	}
	mask, err := parseRights(fields[2])
	if err != nil {
		return nil, err
	}
	sid, err := parseSDDLSID(fields[5], options)
	if err != nil {
		return nil, err
	}
	if typeID == 19 && (mask != 0 || !strings.HasPrefix(formatSID(sid, false), "S-1-17-")) {
		return nil, fmt.Errorf("%w: scoped policy ACE", ErrInvalidExpression)
	}
	result := make([]byte, 8)
	result[0], result[1] = typeID, byte(flags)
	binary.LittleEndian.PutUint32(result[4:8], mask)
	result, err = appendACEObjectFields(result, fields)
	if err != nil {
		return nil, err
	}
	result = append(result, sid...)
	callback := typeID >= 9 && typeID <= 16 || typeID == 21
	switch {
	case typeID == 18:
		if len(fields) != 7 || mask != 0 || formatSID(sid, false) != "S-1-1-0" {
			return nil, fmt.Errorf("%w: resource ACE fields", ErrInvalidExpression)
		}
		application, resourceErr := parseResourceClaim(fields[6], options)
		if resourceErr != nil {
			return nil, resourceErr
		}
		result = append(result, application...)
	case callback:
		if len(fields) != 7 {
			return nil, fmt.Errorf("%w: missing ACE condition", ErrInvalidExpression)
		}
		application, conditionErr := compileCondition(fields[6], options)
		if conditionErr != nil {
			return nil, conditionErr
		}
		result = append(result, application...)
	case len(fields) != 6:
		return nil, fmt.Errorf("%w: application data on ordinary ACE", ErrInvalidExpression)
	}
	length := len(result)
	if length > math.MaxUint16 {
		return nil, fmt.Errorf("%w: ACE length", ErrInvalidExpression)
	}
	binary.LittleEndian.PutUint16(result[2:4], uint16(length))
	return result, nil
}

func appendACEObjectFields(result []byte, fields []string) ([]byte, error) {
	if !objectACEType(result[0]) {
		if fields[3] != "" || fields[4] != "" {
			return nil, fmt.Errorf("%w: object GUID on ordinary ACE", ErrInvalidExpression)
		}
		return result, nil
	}
	result = append(result, 0, 0, 0, 0)
	for i, field := range fields[3:5] {
		if field == "" {
			continue
		}
		guid, err := parseGUID(field)
		if err != nil {
			return nil, err
		}
		result[8] |= 1 << i
		result = append(result, guid...)
	}
	return result, nil
}

func consumeSDDLACE(text string) (string, string, error) {
	depth, quoted := 0, false
	for i := range len(text) {
		switch text[i] {
		case '"':
			quoted = !quoted
		case '(':
			if !quoted {
				depth++
			}
		case ')':
			if !quoted {
				depth--
				if depth == 0 {
					return text[1:i], text[i+1:], nil
				}
			}
		}
	}
	return "", "", fmt.Errorf("%w: unclosed ACE", ErrInvalidExpression)
}

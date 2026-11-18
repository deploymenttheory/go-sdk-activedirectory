package conditions

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

func formatResourceClaim(raw []byte) (string, error) {
	if len(raw) < 16 {
		return "", fmt.Errorf("%w: resource claim header", ErrInvalidDescriptor)
	}
	name, err := resourceUnicodeAt(raw, binary.LittleEndian.Uint32(raw[:4]))
	if err != nil {
		return "", err
	}
	kind := binary.LittleEndian.Uint16(raw[4:6])
	token := ""
	for text, value := range resourceTypeTokens {
		if value == kind {
			token = text
		}
	}
	if token == "" {
		return "", fmt.Errorf("%w: resource claim type", ErrUnrepresentableDescriptor)
	}
	flags := binary.LittleEndian.Uint32(raw[8:12])
	if flags&0xffc0 != 0 {
		return "", fmt.Errorf("%w: resource claim flags", ErrUnrepresentableDescriptor)
	}
	count := uint64(binary.LittleEndian.Uint32(raw[12:16]))
	if count > 4096 || count > (uint64(len(raw))-16)/4 {
		return "", fmt.Errorf("%w: resource claim value table", ErrInvalidDescriptor)
	}
	var result strings.Builder
	result.WriteString("(\"" + escapeAttribute(name) + "\"," + token + "," + fmt.Sprintf("0x%x", flags))
	if result.Len() > 65534 {
		return "", fmt.Errorf("%w: resource claim text size", ErrUnrepresentableDescriptor)
	}
	for i := uint64(0); i < count; i++ {
		offset := binary.LittleEndian.Uint32(raw[16+4*i : 20+4*i])
		value, valueErr := formatResourceValue(raw, offset, kind)
		if valueErr != nil {
			return "", valueErr
		}
		// Relative value offsets may alias. Bound expanded text before adding
		// each value, reserving one separator and the closing parenthesis.
		if len(value) > 65533 || result.Len() > 65533-len(value) {
			return "", fmt.Errorf("%w: resource claim text size", ErrUnrepresentableDescriptor)
		}
		result.WriteByte(',')
		result.WriteString(value)
	}
	result.WriteByte(')')
	return result.String(), nil
}

func resourceUnicodeAt(raw []byte, offset uint32) (string, error) {
	if uint64(offset) < 16 || uint64(offset) > uint64(len(raw)) {
		return "", fmt.Errorf("%w: resource Unicode offset", ErrInvalidDescriptor)
	}
	for position := uint64(offset); position+2 <= uint64(len(raw)); position += 2 {
		if raw[position] == 0 && raw[position+1] == 0 {
			return decodeUTF16(raw[offset:position])
		}
	}
	return "", fmt.Errorf("%w: unterminated resource Unicode", ErrInvalidDescriptor)
}

func formatResourceValue(raw []byte, offset uint32, kind uint16) (string, error) {
	if uint64(offset) < 16 || uint64(offset) > uint64(len(raw)) {
		return "", fmt.Errorf("%w: resource value offset", ErrInvalidDescriptor)
	}
	data := raw[offset:]
	switch kind {
	case 1, 2, 6:
		if len(data) < 8 {
			return "", fmt.Errorf("%w: resource integer bounds", ErrInvalidDescriptor)
		}
		value := binary.LittleEndian.Uint64(data[:8])
		if kind == 1 {
			return strconv.FormatInt(int64(value), 10), nil // #nosec G115 -- interpret the specified two's-complement signed wire field.
		}
		if kind == 6 && value > 1 {
			return "", fmt.Errorf("%w: resource boolean", ErrInvalidDescriptor)
		}
		return strconv.FormatUint(value, 10), nil
	case 3:
		text, err := resourceUnicodeAt(raw, offset)
		if err != nil {
			return "", err
		}
		if strings.ContainsRune(text, '"') {
			return "", fmt.Errorf("%w: resource string quotation", ErrUnrepresentableDescriptor)
		}
		return "\"" + text + "\"", nil
	case 5, 16:
		if len(data) < 4 {
			return "", fmt.Errorf("%w: resource octet header", ErrInvalidDescriptor)
		}
		length := uint64(binary.LittleEndian.Uint32(data[:4]))
		if length > uint64(len(data))-4 {
			return "", fmt.Errorf("%w: resource octet length", ErrInvalidDescriptor)
		}
		data = data[4 : 4+length]
		if kind == 5 {
			if !boundedSID(data) || len(data) != 8+4*int(data[1]) {
				return "", fmt.Errorf("%w: resource SID", ErrInvalidDescriptor)
			}
			return formatSID(data, true), nil
		}
		return hex.EncodeToString(data), nil
	default:
		return "", fmt.Errorf("%w: resource value type", ErrUnrepresentableDescriptor)
	}
}

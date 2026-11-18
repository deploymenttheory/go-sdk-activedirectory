package conditions

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
)

type formattedCondition struct {
	text     string
	code     byte
	sidsOnly bool
	depth    int
}

func formatCondition(raw []byte) (string, error) {
	if len(raw) < 4 || !bytes.Equal(raw[:4], []byte{'a', 'r', 't', 'x'}) {
		return "", fmt.Errorf("%w: application-specific callback", ErrUnrepresentableDescriptor)
	}
	stack := make([]formattedCondition, 0, 8)
	position := 4
	for position < len(raw) {
		if raw[position] == 0 {
			if len(raw)-position > 3 || !allZero(raw[position:]) {
				return "", fmt.Errorf("%w: conditional padding", ErrInvalidDescriptor)
			}
			break
		}
		code := raw[position]
		if conditionLiteralCode(code) || code >= 0xf8 && code <= 0xfb {
			leaf, consumed, err := formatConditionLeaf(raw[position:], 0)
			if err != nil {
				return "", err
			}
			stack = append(stack, leaf)
			position += consumed
		} else {
			var err error
			stack, err = formatConditionOperator(stack, code)
			if err != nil {
				return "", err
			}
			position++
		}
		if len(stack) > 4096 {
			return "", fmt.Errorf("%w: conditional stack size", ErrInvalidDescriptor)
		}
	}
	if len(stack) != 1 || conditionLiteralCode(stack[0].code) {
		return "", fmt.Errorf("%w: incomplete conditional expression", ErrInvalidDescriptor)
	}
	text := stack[0].text
	if stack[0].code >= 0xf8 {
		text = "(" + text + ")"
	}
	return text, nil
}

func allZero(raw []byte) bool {
	for _, value := range raw {
		if value != 0 {
			return false
		}
	}
	return true
}

func conditionLiteralCode(code byte) bool {
	return code >= 1 && code <= 4 || code == 0x10 || code == 0x18 || code == 0x50 || code == 0x51
}

func formatConditionOperator(stack []formattedCondition, code byte) ([]formattedCondition, error) {
	text, arity := "", 0
	for _, operator := range unaryConditionOperators {
		if operator.code == code {
			text, arity = operator.text, 1
		}
	}
	for _, operator := range binaryConditionOperators {
		if operator.code == code {
			text, arity = operator.text, 2
		}
	}
	switch code {
	case 0xa0:
		text, arity = "&&", 2
	case 0xa1:
		text, arity = "||", 2
	case 0xa2:
		text, arity = "!", 1
	}
	if arity == 0 {
		return nil, fmt.Errorf("%w: conditional opcode 0x%02x", ErrUnrepresentableDescriptor, code)
	}
	if len(stack) < arity {
		return nil, fmt.Errorf("%w: conditional stack underflow", ErrInvalidDescriptor)
	}
	operands := stack[len(stack)-arity:]
	depth := 1
	for _, operand := range operands {
		depth = max(depth, operand.depth+1)
	}
	if depth > 64 {
		return nil, fmt.Errorf("%w: conditional nesting", ErrInvalidDescriptor)
	}
	if err := validateConditionOperands(code, operands); err != nil {
		return nil, err
	}
	var formatted string
	switch {
	case arity == 2:
		formatted = "(" + operands[0].text + " " + text + " " + operands[1].text + ")"
	case code == 0xa2:
		formatted = "(!" + operands[0].text + ")"
	default:
		formatted = "(" + text + " " + operands[0].text + ")"
	}
	return append(stack[:len(stack)-arity], formattedCondition{text: formatted, code: code, depth: depth}), nil
}

func validateConditionOperands(code byte, operands []formattedCondition) error {
	valid := true
	switch {
	case code == 0x87 || code == 0x8d:
		valid = operands[0].code == 0xf8 || operands[0].code == 0xfa
	case code >= 0x89 && code <= 0x8c || code >= 0x90 && code <= 0x93:
		valid = operands[0].sidsOnly
	case code >= 0x80 && code <= 0x8f:
		valid = operands[0].code >= 0xf8 && (conditionLiteralCode(operands[1].code) || operands[1].code >= 0xf9)
	case code >= 0xa0 && code <= 0xa2:
		for _, operand := range operands {
			valid = valid && !conditionLiteralCode(operand.code)
		}
	}
	if !valid {
		return fmt.Errorf("%w: conditional operand types", ErrInvalidDescriptor)
	}
	return nil
}

func formatConditionLeaf(raw []byte, depth int) (formattedCondition, int, error) {
	result := formattedCondition{code: raw[0], depth: 1}
	if depth > 8 {
		return result, 0, fmt.Errorf("%w: composite depth", ErrInvalidDescriptor)
	}
	if raw[0] >= 1 && raw[0] <= 4 {
		if len(raw) < 11 || raw[9] < 1 || raw[9] > 3 || raw[10] < 1 || raw[10] > 3 {
			return result, 0, fmt.Errorf("%w: conditional integer", ErrInvalidDescriptor)
		}
		result.text = formatConditionInteger(raw)
		return result, 11, nil
	}
	if len(raw) < 5 {
		return result, 0, fmt.Errorf("%w: conditional leaf header", ErrInvalidDescriptor)
	}
	length := binary.LittleEndian.Uint32(raw[1:5])
	if length > 65535 || uint64(length) > uint64(len(raw))-5 {
		return result, 0, fmt.Errorf("%w: conditional leaf length", ErrInvalidDescriptor)
	}
	data := raw[5 : 5+length]
	var err error
	switch raw[0] {
	case 0x10:
		result.text, err = decodeUTF16(data)
		if strings.ContainsRune(result.text, '"') {
			err = ErrUnrepresentableDescriptor
		}
		result.text = "\"" + result.text + "\""
	case 0x18:
		result.text = "#" + hex.EncodeToString(data)
	case 0x51:
		if !boundedSID(data) || len(data) != 8+4*int(data[1]) {
			return result, 0, fmt.Errorf("%w: conditional SID", ErrInvalidDescriptor)
		}
		result.text, result.sidsOnly = "SID("+formatSID(data, true)+")", true
	case 0x50:
		result.text, result.sidsOnly, err = formatConditionComposite(data, depth+1)
	case 0xf8, 0xf9, 0xfa, 0xfb:
		result.text, err = decodeUTF16(data)
		if raw[0] != 0xf8 {
			prefix := map[byte]string{0xf9: "@USER.", 0xfa: "@RESOURCE.", 0xfb: "@DEVICE."}[raw[0]]
			result.text = prefix + escapeAttribute(result.text)
		}
	default:
		err = ErrUnrepresentableDescriptor
	}
	if err != nil {
		return result, 0, fmt.Errorf("conditional leaf: %w", err)
	}
	return result, 5 + int(length), nil
}

func formatConditionComposite(data []byte, depth int) (string, bool, error) {
	var parts []string
	sidsOnly := true
	for len(data) != 0 {
		if !conditionLiteralCode(data[0]) || data[0] == 0x50 || len(parts) >= 4096 {
			return "", false, fmt.Errorf("%w: composite contents", ErrInvalidDescriptor)
		}
		item, consumed, err := formatConditionLeaf(data, depth)
		if err != nil {
			return "", false, err
		}
		parts = append(parts, item.text)
		sidsOnly = sidsOnly && item.sidsOnly
		data = data[consumed:]
	}
	if len(parts) == 0 {
		return "", false, fmt.Errorf("%w: empty conditional composite", ErrInvalidDescriptor)
	}
	return "{" + strings.Join(parts, ", ") + "}", sidsOnly, nil
}

func formatConditionInteger(raw []byte) string {
	value := binary.LittleEndian.Uint64(raw[1:9])
	prefix := ""
	switch raw[9] {
	case 1:
		prefix = "+"
	case 2:
		prefix = "-"
		value = ^value + 1
	}
	switch raw[10] {
	case 1:
		if value == 0 {
			return prefix + "0"
		}
		return prefix + "0" + strconv.FormatUint(value, 8)
	case 3:
		return prefix + "0x" + strconv.FormatUint(value, 16)
	default:
		return prefix + strconv.FormatUint(value, 10)
	}
}

func decodeUTF16(raw []byte) (string, error) {
	if len(raw)%2 != 0 {
		return "", fmt.Errorf("%w: odd UTF-16 length", ErrInvalidDescriptor)
	}
	words := make([]uint16, 0, len(raw)/2)
	for position := 0; position < len(raw); position += 2 {
		word := binary.LittleEndian.Uint16(raw[position : position+2])
		if word == 0 {
			return "", fmt.Errorf("%w: embedded Unicode NUL", ErrUnrepresentableDescriptor)
		}
		words = append(words, word)
	}
	for i := 0; i < len(words); i++ {
		if words[i] >= 0xd800 && words[i] <= 0xdbff {
			if i+1 == len(words) || words[i+1] < 0xdc00 || words[i+1] > 0xdfff {
				return "", fmt.Errorf("%w: unpaired UTF-16 surrogate", ErrUnrepresentableDescriptor)
			}
			i++
		} else if words[i] >= 0xdc00 && words[i] <= 0xdfff {
			return "", fmt.Errorf("%w: unpaired UTF-16 surrogate", ErrUnrepresentableDescriptor)
		}
	}
	return string(utf16.Decode(words)), nil
}

func escapeAttribute(text string) string {
	var result strings.Builder
	for _, char := range text {
		if strings.ContainsRune("!&()><=|% \"", char) || char < 0x20 {
			for _, word := range utf16.Encode([]rune{char}) {
				fmt.Fprintf(&result, "%%%04x", word)
			}
		} else {
			result.WriteRune(char)
		}
	}
	return result.String()
}

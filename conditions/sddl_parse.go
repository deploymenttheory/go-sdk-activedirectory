package conditions

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

// ParseSDDL compiles a complete SDDL descriptor without native APIs. Domain or
// machine-relative aliases require ParseSDDLWithOptions and explicit SID context.
func ParseSDDL(input string) (*Descriptor, error) {
	return ParseSDDLWithOptions(input, SDDLOptions{})
}

// ParseSDDLWithOptions compiles SDDL using caller-supplied identity context.
func ParseSDDLWithOptions(input string, options SDDLOptions) (*Descriptor, error) {
	if !validInput(input) {
		return nil, fmt.Errorf("%w: invalid SDDL input", ErrInvalidExpression)
	}
	parts, err := splitSDDL(input)
	if err != nil {
		return nil, err
	}
	result := make([]byte, descriptorHeaderSize)
	result[0] = 1
	control := uint16(controlSelfRelative)
	for _, component := range []struct {
		name byte
		at   int
	}{{'S', 12}, {'D', 16}, {'O', 4}, {'G', 8}} {
		text, exists := parts[component.name]
		if !exists {
			continue
		}
		var content []byte
		if component.name == 'O' || component.name == 'G' {
			content, err = parseSDDLSID(text, options)
		} else {
			var flags uint16
			content, flags, err = parseSDDLACL(text, component.name, options)
			control |= flags
		}
		if err != nil {
			return nil, err
		}
		if len(content) != 0 {
			length := len(result)
			if length < descriptorHeaderSize || length > maxDescriptorBytes || length > maxDescriptorBytes-len(content) {
				return nil, fmt.Errorf("%w: SDDL descriptor size", ErrInvalidExpression)
			}
			binary.LittleEndian.PutUint32(result[component.at:component.at+4], uint32(length))
			result = append(result, content...)
		}
	}
	binary.LittleEndian.PutUint16(result[2:4], control)
	return ParseDescriptor(result)
}

func splitSDDL(input string) (map[byte]string, error) {
	result := make(map[byte]string, 4)
	position := 0
	for position < len(input) {
		if len(input)-position < 2 || !strings.ContainsRune("OGDS", rune(input[position])) || input[position+1] != ':' {
			return nil, fmt.Errorf("%w: SDDL component at byte %d", ErrInvalidExpression, position)
		}
		name := input[position]
		if _, duplicate := result[name]; duplicate {
			return nil, fmt.Errorf("%w: duplicate SDDL component", ErrInvalidExpression)
		}
		start := position + 2
		position = start
		depth, quoted := 0, false
		for position < len(input) {
			c := input[position]
			if c == '"' {
				quoted = !quoted
			}
			if !quoted {
				if depth == 0 && position+1 < len(input) && input[position+1] == ':' && strings.ContainsRune("OGDS", rune(c)) {
					break
				}
				if c == '(' {
					depth++
				}
				if c == ')' {
					depth--
				}
				if depth < 0 || depth > 64 {
					return nil, fmt.Errorf("%w: SDDL nesting", ErrInvalidExpression)
				}
			}
			position++
		}
		if depth != 0 || quoted {
			return nil, fmt.Errorf("%w: unclosed SDDL component", ErrInvalidExpression)
		}
		result[name] = strings.TrimSpace(input[start:position])
	}
	return result, nil
}

func parseSDDLACL(text string, kind byte, options SDDLOptions) ([]byte, uint16, error) {
	present, protected, requested, inherited := uint16(controlDACLPresent), uint16(0x1000), uint16(0x100), uint16(0x400)
	if kind == 'S' {
		present, protected, requested, inherited = controlSACLPresent, 0x2000, 0x200, 0x800
	}
	flags := present
	for len(text) != 0 && text[0] != '(' {
		switch {
		case strings.HasPrefix(text, "P"):
			flags |= protected
			text = text[1:]
		case strings.HasPrefix(text, "AR"):
			flags |= requested
			text = text[2:]
		case strings.HasPrefix(text, "AI"):
			flags |= inherited
			text = text[2:]
		case text == "NO_ACCESS_CONTROL":
			return nil, flags, nil
		default:
			return nil, 0, fmt.Errorf("%w: ACL syntax", ErrInvalidExpression)
		}
	}
	raw := []byte{2, 0, 8, 0, 0, 0, 0, 0}
	count := 0
	for len(text) != 0 {
		if text[0] != '(' {
			return nil, 0, fmt.Errorf("%w: expected ACE", ErrInvalidExpression)
		}
		aceText, rest, err := consumeSDDLACE(text)
		if err != nil {
			return nil, 0, err
		}
		ace, err := parseSDDLACE(aceText, kind, options)
		if err != nil {
			return nil, 0, err
		}
		if objectACEType(ace[0]) {
			raw[0] = 4
		}
		raw = append(raw, ace...)
		count++
		text = rest
	}
	length := len(raw)
	if length > math.MaxUint16 || count > math.MaxUint16 {
		return nil, 0, fmt.Errorf("%w: ACL wire bounds", ErrInvalidExpression)
	}
	binary.LittleEndian.PutUint16(raw[2:4], uint16(length))
	binary.LittleEndian.PutUint16(raw[4:6], uint16(count))
	return raw, flags, nil
}

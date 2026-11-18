package conditions

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ErrUnrepresentableDescriptor identifies valid binary data without a supported
// lossless SDDL meaning. The original Descriptor can still be marshaled as binary.
var ErrUnrepresentableDescriptor = errors.New("security descriptor cannot be represented as SDDL")

// SDDL formats all supported descriptor components without resolving identities
// or evaluating access. It refuses opaque ACEs and control bits that SDDL cannot
// express. Storage order, reserved fields and capacity remain in MarshalBinary;
// SDDL represents their security meaning rather than their original byte layout.
func (descriptor *Descriptor) SDDL() (string, error) {
	if descriptor == nil || len(descriptor.raw) < descriptorHeaderSize {
		return "", fmt.Errorf("%w: uninitialized descriptor", ErrInvalidDescriptor)
	}
	control := binary.LittleEndian.Uint16(descriptor.raw[2:4])
	const represented = controlSelfRelative | controlDACLPresent | controlSACLPresent | 0x3f00
	if control & ^uint16(represented) != 0 {
		return "", fmt.Errorf("%w: control bits", ErrUnrepresentableDescriptor)
	}
	var result strings.Builder
	for _, item := range []struct {
		name string
		at   int
	}{{"O:", 4}, {"G:", 8}} {
		if offset := binary.LittleEndian.Uint32(descriptor.raw[item.at : item.at+4]); offset != 0 {
			result.WriteString(item.name)
			result.WriteString(formatSID(descriptor.raw[offset:], true))
		}
	}
	for _, item := range []struct {
		kind byte
		acl  ACL
	}{{'D', descriptor.DACL()}, {'S', descriptor.SACL()}} {
		if !item.acl.Present {
			continue
		}
		result.WriteByte(item.kind)
		result.WriteByte(':')
		p, ar, ai := uint16(0x1000), uint16(0x100), uint16(0x400)
		if item.kind == 'S' {
			p, ar, ai = 0x2000, 0x200, 0x800
		}
		for _, flag := range []struct {
			bit  uint16
			text string
		}{{p, "P"}, {ar, "AR"}, {ai, "AI"}} {
			if control&flag.bit != 0 {
				result.WriteString(flag.text)
			}
		}
		if item.acl.Null {
			result.WriteString("NO_ACCESS_CONTROL")
		}
		for _, ace := range item.acl.ACEs {
			text, err := formatSDDLACE(ace)
			if err != nil {
				return "", err
			}
			result.WriteString(text)
		}
	}
	if result.Len() == 0 {
		return "", fmt.Errorf("%w: no SDDL components", ErrUnrepresentableDescriptor)
	}
	text := result.String()
	// A bounded binary descriptor may contain opaque combinations that SDDL
	// cannot express (for example an unknown scoped-policy mask or ACL role).
	// Confirm representability without silently returning unusable text.
	if _, err := ParseSDDL(text); err != nil {
		return "", fmt.Errorf("%w: formatted components: %w", ErrUnrepresentableDescriptor, err)
	}
	return text, nil
}

func formatSDDLACE(raw []byte) (string, error) {
	kind := ""
	for token, code := range aceTypeTokens {
		if raw[0] == code {
			kind = token
			break
		}
	}
	if kind == "" {
		return "", fmt.Errorf("%w: ACE type 0x%02x", ErrUnrepresentableDescriptor, raw[0])
	}
	var flags strings.Builder
	for _, flag := range []string{"OI", "CI", "NP", "IO", "ID", "TP", "SA", "FA"} {
		if uint32(raw[1])&aceFlagTokens[flag] != 0 {
			flags.WriteString(flag)
		}
	}
	mask := formatAccessMask(binary.LittleEndian.Uint32(raw[4:8]), raw[0])
	guids := [2]string{}
	position := 8
	if objectACEType(raw[0]) {
		objectFlags := binary.LittleEndian.Uint32(raw[8:12])
		if objectFlags & ^uint32(3) != 0 {
			return "", fmt.Errorf("%w: opaque object ACE flags", ErrUnrepresentableDescriptor)
		}
		position = 12
		for i := range guids {
			if objectFlags&(1<<i) != 0 {
				guids[i] = formatGUID(raw[position : position+16])
				position += 16
			}
		}
	}
	sid := raw[position:]
	trustee := formatSID(sid, true)
	position += 8 + 4*int(sid[1])
	result := "(" + kind + ";" + flags.String() + ";" + mask + ";" + guids[0] + ";" + guids[1] + ";" + trustee
	switch {
	case raw[0] >= 9 && raw[0] <= 16 || raw[0] == 21:
		condition, err := formatCondition(raw[position:])
		if err != nil {
			return "", err
		}
		result += ";" + condition
	case raw[0] == 18:
		claim, err := formatResourceClaim(raw[position:])
		if err != nil {
			return "", err
		}
		result += ";" + claim
	case position != len(raw):
		return "", fmt.Errorf("%w: opaque ACE trailing bytes", ErrUnrepresentableDescriptor)
	}
	return result + ")", nil
}

func formatGUID(raw []byte) string {
	value := [16]byte{}
	copy(value[:], raw)
	value[0], value[3] = value[3], value[0]
	value[1], value[2] = value[2], value[1]
	value[4], value[5] = value[5], value[4]
	value[6], value[7] = value[7], value[6]
	text := hex.EncodeToString(value[:])
	return text[:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:]
}

func formatAccessMask(mask uint32, kind byte) string {
	if mask == 0 {
		return ""
	}
	if kind != 17 {
		for _, token := range []string{"FA", "FR", "FW", "FX", "KA", "KR", "KW"} {
			if aceRightTokens[token] == mask {
				return token
			}
		}
	}
	tokens := []string{"CC", "DC", "LC", "SW", "RP", "WP", "DT", "LO", "CR", "SD", "RC", "WD", "WO", "AS", "MA", "GA", "GX", "GW", "GR"}
	if kind == 17 {
		tokens = []string{"NW", "NR", "NX"}
	}
	remaining, text := mask, ""
	for _, token := range tokens {
		if remaining&aceRightTokens[token] != 0 {
			text += token
			remaining &^= aceRightTokens[token]
		}
	}
	if remaining != 0 {
		return fmt.Sprintf("0x%x", mask)
	}
	return text
}

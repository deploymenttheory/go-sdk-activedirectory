package conditions

import "fmt"

// Compile compiles one conditional allow/deny ACE into a DACL-only SDDL string
// using the portable MS-DTYP codec. It does not resolve claims or evaluate access.
func Compile(ace ACE) (string, error) {
	condition, err := ace.validate()
	if err != nil {
		return "", err
	}
	kind := "XA"
	if ace.Deny {
		kind = "XD"
	}
	return NormalizeSDDL(fmt.Sprintf("D:(%s;;0x%x;;;%s;%s)", kind, ace.AccessMask, ace.TrusteeSID, condition))
}

// NormalizeSDDL parses and formats all supported SDDL components portably. It
// neither resolves domain-relative aliases nor verifies claim/schema existence.
func NormalizeSDDL(input string) (string, error) {
	descriptor, err := ParseSDDL(input)
	if err != nil {
		return "", err
	}
	return descriptor.SDDL()
}

// DescriptorBytes compiles complete SDDL into owned self-relative bytes without
// native APIs. Domain-relative aliases require ParseSDDLWithOptions instead.
func DescriptorBytes(input string) ([]byte, error) {
	descriptor, err := ParseSDDL(input)
	if err != nil {
		return nil, err
	}
	return descriptor.MarshalBinary()
}

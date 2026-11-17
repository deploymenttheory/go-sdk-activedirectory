//go:build windows && (amd64 || arm64)

package engine

import "github.com/deploymenttheory/go-sdk-activedirectory/conditions"

func (*InternalLdapSession) InternalValidateCentralAccessDescriptor(value string) error {
	_, err := conditions.NormalizeSDDL(value)
	return err
}

func (*InternalLdapSession) InternalValidateCentralAccessCondition(value string) error {
	_, err := conditions.Compile(
		conditions.ACE{
			TrusteeSID: "S-1-1-0",
			AccessMask: 0x10000000,
			Condition:  conditions.Raw(value),
		},
	)
	return err
}

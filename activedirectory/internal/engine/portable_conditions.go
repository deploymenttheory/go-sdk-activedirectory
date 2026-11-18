package engine

import "github.com/deploymenttheory/go-sdk-activedirectory/conditions"

// InternalValidateCentralAccessDescriptor validates complete SDDL locally using
// the portable codec, without resolving identities or submitting a mutation.
func (*InternalPortableSession) InternalValidateCentralAccessDescriptor(value string) error {
	_, err := conditions.NormalizeSDDL(value)
	return err
}

// InternalValidateCentralAccessCondition validates resource-condition syntax.
// The temporary ACE supplies parser context only; its result is never applied.
func (*InternalPortableSession) InternalValidateCentralAccessCondition(value string) error {
	_, err := conditions.Compile(conditions.ACE{
		TrusteeSID: "S-1-1-0", AccessMask: 0x10000000, Condition: conditions.Raw(value),
	})
	return err
}

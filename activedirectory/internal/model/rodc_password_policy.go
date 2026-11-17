package model

import (
	"errors"
	"slices"
)

var (
	ErrInvalidRODCPasswordPolicy = errors.New("invalid RODC password replication request")
	ErrRODCPasswordPolicyTarget  = errors.New(
		"password replication requires an RODC computer in the connected full domain replica",
	)
	ErrRODCPasswordPolicyCapability = errors.New(
		"RODC password replication capability or required observation unavailable",
	)
	ErrRODCPasswordPolicyPermission = errors.New("RODC password replication access denied")
)

type RODCPasswordReplicationList uint8

const (
	RODCPasswordAllowed RODCPasswordReplicationList = iota
	RODCPasswordDenied
)

func InternalRODCPasswordReplicationListAttribute(
	list RODCPasswordReplicationList,
) (string, error) {
	switch list {
	case RODCPasswordAllowed:
		return "msDS-RevealOnDemandGroup", nil
	case RODCPasswordDenied:
		return "msDS-NeverRevealGroup", nil
	default:
		return "", ErrInvalidRODCPasswordPolicy
	}
}

type RODCPasswordReplicationUsageKind uint8

const (
	RODCPasswordRevealed RODCPasswordReplicationUsageKind = iota
	RODCPasswordAuthenticated
)

// The target is explicitly the RODC computer object, using the shared Identity
// constructors. Server/DSA object identities, DNS names and discovery are not
// guessed. Partition defaults to the connected server's full domain NC.
type RODCPasswordReplicationOptions struct {
	Partition  string
	Properties []string
	// Collection uses MaxObjects, MaxRanges and MaxBytes. MaxObjects includes
	// received link values and fetched principal rows, not just unique outputs.
	// MaxGroups/MaxDepth are inapplicable and must be zero. Resultant policy has
	// no collection and requires all limits to be zero.
	Limits MembershipLimits
}

type RODCResultantPasswordReplicationPolicy int64

const (
	RODCPasswordPolicyUnknown      RODCResultantPasswordReplicationPolicy = -1
	RODCPasswordPolicyDenyExplicit RODCResultantPasswordReplicationPolicy = 0
	RODCPasswordPolicyAllow        RODCResultantPasswordReplicationPolicy = 1
	RODCPasswordPolicyDenyImplicit RODCResultantPasswordReplicationPolicy = 2
)

func (p RODCResultantPasswordReplicationPolicy) Known() bool { return p >= 0 && p <= 2 }

// Policy is the server's constructed attribute, never a local approximation of
// nested membership. Raw retains absent, malformed and unknown values. Complete
// only describes this read; it does not mean permission to replicate secrets,
// current cache state, or replication convergence.
type RODCResultantPasswordReplicationResult struct {
	Controller, Account IdentityResult
	Raw                 Object
	Policy              *RODCResultantPasswordReplicationPolicy
	Complete            bool
}

func InternalRodcPasswordProperties(extra []string) []string {
	return InternalMembershipProperties(
		append(slices.Clone(extra), "msDS-isRODC", "userAccountControl"),
	)
}

func InternalValidateRODCPasswordTarget(object Object) error {
	if !InternalMembershipHasClass(object, "computer") {
		return ErrRODCPasswordPolicyTarget
	}
	value, err := object.Values("msDS-isRODC").Single()
	if err != nil {
		return errors.Join(ErrRODCPasswordPolicyCapability, err)
	}
	rodc, err := value.Bool()
	if err != nil {
		return err
	}
	if !rodc {
		return ErrRODCPasswordPolicyTarget
	}
	value, err = object.Values("userAccountControl").Single()
	if err != nil {
		return err
	}
	flags, err := value.Flags32()
	if err != nil {
		return err
	}
	if !flags.Has(0x04000000) {
		return ErrRODCPasswordPolicyTarget
	}
	_, err = InternalDecodeMembershipPrincipal(object, Endpoint{})
	return err
}

func InternalValidateRODCPasswordPrincipal(object Object, allowGroup bool) error {
	if InternalMembershipHasClass(object, "group") {
		if !allowGroup {
			return ErrUnsupportedIdentity
		}
		value, err := object.Values("groupType").Single()
		if err != nil {
			return err
		}
		flags, err := value.Flags32()
		if err != nil {
			return err
		}
		if !flags.Has(InternalGroupSecurityBit) {
			return ErrUnsupportedIdentity
		}
		return nil
	}
	if !InternalMembershipHasClass(object, "user") {
		return ErrUnsupportedIdentity
	}
	return nil
}

func InternalRodcPasswordError(err error) error {
	var native *LDAPError
	if errors.As(err, &native) && native.Code == 50 {
		return errors.Join(ErrRODCPasswordPolicyPermission, err)
	}
	return err
}

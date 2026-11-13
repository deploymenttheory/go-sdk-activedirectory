package activedirectory

import (
	"context"
	"errors"
	"slices"
)

var (
	ErrInvalidRODCPasswordPolicy    = errors.New("invalid RODC password replication request")
	ErrRODCPasswordPolicyTarget     = errors.New("password replication requires an RODC computer in the connected full domain replica")
	ErrRODCPasswordPolicyCapability = errors.New("RODC password replication capability or required observation unavailable")
	ErrRODCPasswordPolicyPermission = errors.New("RODC password replication access denied")
)

type RODCPasswordReplicationList uint8

const (
	RODCPasswordAllowed RODCPasswordReplicationList = iota
	RODCPasswordDenied
)

func (list RODCPasswordReplicationList) attribute() (string, error) {
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

func rodcPasswordProperties(extra []string) []string {
	return membershipProperties(append(slices.Clone(extra), "msDS-isRODC", "userAccountControl"))
}

func validateRODCPasswordTarget(object Object) error {
	if !membershipHasClass(object, "computer") {
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
	_, err = decodeMembershipPrincipal(object, Endpoint{})
	return err
}

func validateRODCPasswordPrincipal(object Object, allowGroup bool) error {
	if membershipHasClass(object, "group") {
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
		if !flags.Has(groupSecurityBit) {
			return ErrUnsupportedIdentity
		}
		return nil
	}
	if !membershipHasClass(object, "user") {
		return ErrUnsupportedIdentity
	}
	return nil
}

func rodcPasswordServer(ctx context.Context, c *Client, session directorySession, root RootDSE, partition string, write bool) error {
	if err := root.Capabilities().RequireADDS("RODCPasswordReplication"); err != nil {
		return err
	}
	if root.DefaultNamingContext == nil || !membershipSameDN(partition, *root.DefaultNamingContext) || c.config.Endpoint.Port == 3268 || c.config.Endpoint.Port == 3269 {
		return ErrRODCPasswordPolicyTarget
	}
	server, err := readObjectSyncServer(ctx, session)
	if err != nil {
		return errors.Join(ErrRODCPasswordPolicyCapability, err)
	}
	attribute := "msDS-hasMasterNCs"
	if server.rodc {
		attribute = "msDS-hasFullReplicaNCs"
	}
	values, state := server.dsa.Attribute(attribute)
	if state != AttributePresent || !slices.ContainsFunc(values, func(value []byte) bool { return membershipSameDN(string(value), partition) }) {
		return ErrRODCPasswordPolicyTarget
	}
	if write && server.rodc {
		return ErrRODCPasswordPolicyTarget
	}
	return nil
}

func rodcPasswordError(err error) error {
	var native *LDAPError
	if errors.As(err, &native) && native.Code == 50 {
		return errors.Join(ErrRODCPasswordPolicyPermission, err)
	}
	return err
}

func (c *Client) AccountResultantPasswordReplicationPolicy(ctx context.Context, controller, account Identity, options RODCPasswordReplicationOptions) (result RODCResultantPasswordReplicationResult, err error) {
	if options.Limits != (MembershipLimits{}) {
		return result, ErrInvalidRODCPasswordPolicy
	}
	if err = validateIdentityOperation(controller, membershipResolveOptions(controller, options.Partition, nil)); err != nil {
		return result, err
	}
	if err = validateIdentityOperation(account, membershipResolveOptions(account, options.Partition, options.Properties)); err != nil {
		return result, err
	}
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	err = c.read(ctx, func(ctx context.Context) error {
		root, readErr := readIdentityRoot(ctx, c.session)
		if readErr != nil {
			return readErr
		}
		result.Controller, readErr = resolveIdentitySession(ctx, c.session, c.config, root, controller, membershipResolveOptions(controller, options.Partition, rodcPasswordProperties(nil)))
		if readErr != nil {
			return readErr
		}
		if err := rodcPasswordServer(ctx, c, c.session, root, result.Controller.Partition, false); err != nil {
			return err
		}
		if err := validateRODCPasswordTarget(*result.Controller.Object); err != nil {
			return err
		}
		result.Account, readErr = resolveIdentitySession(ctx, c.session, c.config, root, account, membershipResolveOptions(account, result.Controller.Partition, options.Properties))
		if readErr != nil {
			return readErr
		}
		if !membershipHasClass(*result.Account.Object, "user") {
			return ErrUnsupportedIdentity
		}
		principal, readErr := decodeMembershipPrincipal(*result.Account.Object, c.config.Endpoint)
		if readErr != nil {
			return readErr
		}
		rodc, readErr := decodeMembershipPrincipal(*result.Controller.Object, c.config.Endpoint)
		if readErr != nil {
			return readErr
		}
		reader, ok := c.session.(objectSyncPolicySession)
		if !ok || !slices.Contains(root.SupportedControls, objectSyncDNInputOID) {
			return ErrRODCPasswordPolicyCapability
		}
		attrs, readErr := reader.objectSyncPasswordPolicy(ctx, objectGUIDTarget(rodc.GUID), objectGUIDTarget(principal.GUID))
		result.Raw = Object{DistinguishedName: result.Controller.Object.DistinguishedName, Attributes: attrs, RequestedProperties: []string{"msDS-IsUserCachableAtRodc"}}
		value, valueErr := result.Raw.Values("msDS-IsUserCachableAtRodc").Single()
		if valueErr != nil {
			return errors.Join(readErr, ErrRODCPasswordPolicyCapability, valueErr)
		}
		number, valueErr := value.Int64()
		if valueErr != nil {
			return errors.Join(readErr, valueErr)
		}
		policy := RODCResultantPasswordReplicationPolicy(number)
		result.Policy = &policy
		result.Complete = readErr == nil
		return readErr
	})
	return result, rodcPasswordError(err)
}

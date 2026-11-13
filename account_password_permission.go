package activedirectory

import (
	"context"
	"errors"
	"slices"
)

var ErrAccountPasswordPermission = errors.New("account password-change permission is unknown or could not be established")

type directoryDACLSession interface {
	directorySession
	readDirectoryDACL(context.Context, string, []string) (Object, error)
	encodeDACL([]byte, [][]byte) ([]byte, error)
}

// AccountPasswordPermission describes SELF/Everyone Change-Password ACEs.
// CannotChangePassword is the recognized deny-pattern observation, not an
// effective-access check or a promise that a password change will succeed.
// Nil means the descriptor/pattern is unknown; it is never a userAccountControl
// bit. The original descriptor remains available in Raw.
type AccountPasswordPermission struct {
	DistinguishedName    string
	GUID                 *GUID
	CannotChangePassword *bool
	Self, Everyone       PasswordChangeACEObservation
	UnknownACE           bool
	Raw                  Object
}

type AccountPasswordPermissionResult struct {
	Permission  *AccountPasswordPermission
	Observation IdentityResult
}

type AccountPasswordPermissionMutationResult struct {
	Mutation      ObjectMutationResult
	Before, After *AccountPasswordPermission
	Changed       bool
}

// AccountPasswordChangePermission reads the DACL's Change-Password ACE pattern
// using the shared account identity/class rules and a critical DACL-only control.
func (c *Client) AccountPasswordChangePermission(ctx context.Context, identity Identity, options ResolveIdentityOptions) (AccountPasswordPermissionResult, error) {
	var result AccountPasswordPermissionResult
	if options.Target > IdentityTargetAccount {
		return result, ErrInvalidIdentity
	}
	options = accountControlIdentity(identity, options.Partition, options.Properties)
	if err := validateIdentityOperation(identity, options); err != nil {
		return result, err
	}
	err := c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		result.Observation, err = resolveIdentitySession(ctx, c.session, c.config, root, identity, options)
		if err != nil {
			return err
		}
		if err := accountControlClass(*result.Observation.Object, root.Capabilities().Type); err != nil {
			return err
		}
		value, err := result.Observation.Object.Values("objectGUID").Single()
		if err != nil {
			return err
		}
		guid, err := value.GUID()
		if err != nil {
			return err
		}
		session, ok := c.session.(directoryDACLSession)
		if !ok {
			return ErrUnsupported
		}
		if !slices.Contains(root.SupportedControls, directorySDFlagsControl) {
			return ErrObjectControlUnsupported
		}
		observed, _, _, err := readAccountPasswordPermission(ctx, session, root, result.Observation.Partition, guid, options.Properties)
		result.Permission = &observed
		return err
	})
	return result, err
}

func decodeAccountPasswordPermission(object Object) (AccountPasswordPermission, []byte, directoryDACL, error) {
	result := AccountPasswordPermission{DistinguishedName: object.DistinguishedName, Raw: object}
	var acl directoryDACL
	value, err := object.Values("objectGUID").Single()
	if err != nil {
		return result, nil, acl, errors.Join(ErrAccountPasswordPermission, err)
	}
	guid, err := value.GUID()
	if err != nil {
		return result, nil, acl, errors.Join(ErrAccountPasswordPermission, err)
	}
	result.GUID = &guid
	value, err = object.Values("nTSecurityDescriptor").Single()
	if err != nil {
		return result, nil, acl, errors.Join(ErrAccountPasswordPermission, err)
	}
	raw := value.Bytes()
	acl, err = decodeDirectoryDACL(raw)
	if err != nil {
		return result, raw, acl, errors.Join(ErrAccountPasswordPermission, err)
	}
	result.Self, result.Everyone, result.CannotChangePassword, result.UnknownACE = observePasswordChangeACL(acl)
	return result, raw, acl, nil
}

func readAccountPasswordPermission(ctx context.Context, session directoryDACLSession, root RootDSE, partition string, guid GUID, properties []string) (AccountPasswordPermission, []byte, directoryDACL, error) {
	object, readErr := session.readDirectoryDACL(ctx, objectGUIDTarget(guid), properties)
	result, raw, acl, err := decodeAccountPasswordPermission(object)
	if readErr != nil || err != nil {
		result.CannotChangePassword = nil
		return result, raw, acl, errors.Join(readErr, err)
	}
	if result.GUID == nil || *result.GUID != guid {
		result.CannotChangePassword = nil
		return result, raw, acl, ErrInvalidResult
	}
	identity, err := IdentityByDN(object.DistinguishedName)
	if err == nil {
		_, _, err = identityPartition(identity, partition, root)
	}
	if err != nil {
		result.CannotChangePassword = nil
		return result, raw, acl, err
	}
	return result, raw, acl, nil
}

// SetAccountCannotChangePassword edits only explicit SELF/Everyone object ACEs
// for the Change-Password extended right. False installs allow rules rather
// than merely clearing a UAC bit or removing all matching rights. It preserves
// unrelated/inherited/opaque ACE bytes and never modifies a parent DACL.
// Default edits preserve the observed snapshot, not concurrent unseen changes.
// ExpectedVersion requires a supported critical server assertion and a write.
func (c *Client) SetAccountCannotChangePassword(ctx context.Context, identity Identity, cannot bool, options ObjectMutationOptions) (AccountPasswordPermissionMutationResult, error) {
	var result AccountPasswordPermissionMutationResult
	resolve := accountControlIdentity(identity, options.Partition, options.Properties)
	if err := validateIdentityOperation(identity, resolve); err != nil {
		return result, err
	}
	for _, property := range options.Properties {
		if property == "1.1" {
			return result, ErrInvalidProperty
		}
	}
	properties := objectWriteProperties(options, nil)
	var err error
	result.Mutation, err = c.objectMutationIdentity(ctx, identity, options, resolve, func(ctx context.Context, writer ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		if err := accountControlClass(*observed.Object, root.Capabilities().Type); err != nil {
			return err
		}
		session, ok := writer.(directoryDACLSession)
		if !ok {
			return ErrUnsupported
		}
		if !slices.Contains(root.SupportedControls, directorySDFlagsControl) {
			return ErrObjectControlUnsupported
		}
		before, raw, acl, err := readAccountPasswordPermission(ctx, session, root, mutation.Partition, *mutation.TargetGUID, properties)
		result.Before = &before
		mutation.Before = &before.Raw
		if err != nil {
			return err
		}
		if !cannot && (before.Self.InheritedDeny || before.Everyone.InheritedDeny) {
			return ErrAccountPasswordPermission
		}
		aces, changed, err := changePasswordPermissionACEs(acl, cannot)
		if err != nil {
			return err
		}
		result.Changed = changed
		_, _, planned, unknown := observePasswordChangeACL(directoryDACL{aces: aces})
		if unknown || planned == nil || *planned != cannot {
			// Do not dispatch a descriptor that is already known to leave the
			// requested reference pattern ambiguous (for example mixed rights).
			return ErrAccountPasswordPermission
		}
		if !changed {
			if options.ExpectedVersion != nil {
				return ErrObjectControlUnsupported
			}
			result.After = result.Before
			mutation.After = mutation.Before
			mutation.ReadbackComplete = true
			mutation.Verified = before.CannotChangePassword != nil && *before.CannotChangePassword == cannot
			if !mutation.Verified {
				return ErrAccountPasswordPermission
			}
			return nil
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, options, *mutation.TargetGUID, false)
		if err != nil {
			return err
		}
		updated, err := session.encodeDACL(raw, aces)
		if err != nil {
			return err
		}
		controls = append(controls, ldapWriteControl{oid: directorySDFlagsControl, critical: true, value: directoryDACLControlValue})
		write := ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*mutation.TargetGUID), modifications: []ldapAttributeModification{{operation: 2, attribute: "nTSecurityDescriptor", values: [][]byte{updated}}}, controls: controls}
		if err := submitObjectWrite(ctx, writer, write, false, mutation); err != nil {
			return err
		}
		after, _, actual, err := readAccountPasswordPermission(ctx, session, root, mutation.Partition, *mutation.TargetGUID, properties)
		result.After = &after
		mutation.After = &after.Raw
		mutation.ReadbackCandidates = []Object{after.Raw}
		if err != nil {
			return errors.Join(ErrObjectReadback, err)
		}
		mutation.ReadbackComplete = true
		if after.CannotChangePassword == nil || *after.CannotChangePassword != cannot || !directoryACEsRetained(aces, actual.aces) {
			return errors.Join(ErrAccountPasswordPermission, ErrObjectVerification)
		}
		mutation.Verified = true
		return nil
	})
	return result, err
}

func directoryACEsRetained(expected, actual [][]byte) bool {
	counts := make(map[string]int, len(actual))
	for _, ace := range actual {
		counts[string(ace)]++
	}
	for _, ace := range expected {
		if counts[string(ace)] == 0 {
			return false
		}
		counts[string(ace)]--
	}
	return true
}

package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strings"
)

type ouProtectionSession interface {
	ldapWriteSession
	readOUDACL(context.Context, string) (Object, error)
	editOUDACL([]byte, uint32, bool) ([]byte, bool, error)
}

// OUProtectionStep records one object's ACL observation and write. Parent and
// OU changes are separate LDAP operations; an earlier accepted write survives
// later failure. Neither partial success nor uncertainty triggers rollback.
type OUProtectionStep struct {
	TargetDN          string
	TargetGUID        *GUID
	Before, After     *Object
	State             ObjectWriteState
	Changed, Verified bool
}

type OUProtectionResult struct {
	Object                          ObjectMutationResult
	Steps                           []OUProtectionStep
	ProtectedFromAccidentalDeletion *bool
}

// SetOrganizationalUnitProtection enables/disables the reference ACL pattern.
// Enabling can add Everyone deny-delete-child on the parent, affecting sibling
// deletion permissions. Disabling changes only explicit protection rights on
// this OU. Inherited/unknown rules and the parent's ACL are never removed.
func (c *Client) SetOrganizationalUnitProtection(ctx context.Context, identity Identity, protect bool, options ObjectMutationOptions) (OUProtectionResult, error) {
	var result OUProtectionResult
	if err := validateObjectOptions(identity, options); err != nil {
		return result, err
	}
	var err error
	result.Object, err = c.objectMutation(ctx, identity, options, func(ctx context.Context, session ldapWriteSession, root RootDSE, resolved IdentityResult, object *ObjectMutationResult) error {
		if _, err := decodeOrganizationalUnit(*resolved.Object); err != nil {
			return err
		}
		return changeOUProtection(ctx, session, root, c.config, object, protect, options, &result)
	})
	return result, err
}

func ouDescriptor(object Object) ([]byte, *GUID, error) {
	value, err := object.Values("objectGUID").Single()
	if err != nil {
		return nil, nil, errors.Join(ErrOUProtection, err)
	}
	guid, err := value.GUID()
	if err != nil {
		return nil, nil, errors.Join(ErrOUProtection, err)
	}
	descriptor, err := object.Values("nTSecurityDescriptor").Single()
	if err != nil {
		return nil, &guid, errors.Join(ErrOUProtection, err)
	}
	return descriptor.Bytes(), &guid, nil
}

type ouProtectionSnapshot struct {
	raw, parentRaw []byte
	acl, parentACL ouDACL
	parentDN       string
}

func prepareOUProtection(ctx context.Context, session ouProtectionSession, root RootDSE, config Config, object *ObjectMutationResult, result *OUProtectionResult) (ouProtectionSnapshot, error) {
	var snapshot ouProtectionSnapshot
	before, err := session.readOUDACL(ctx, objectGUIDTarget(*object.TargetGUID))
	result.Steps = append(result.Steps, OUProtectionStep{TargetDN: before.DistinguishedName, Before: &before})
	if err != nil {
		return snapshot, errors.Join(ErrOUProtection, err)
	}
	raw, guid, err := ouDescriptor(before)
	if err != nil || *guid != *object.TargetGUID {
		return snapshot, errors.Join(ErrOUProtection, ErrInvalidResult, err)
	}
	result.Steps[0].TargetGUID = guid
	acl, err := decodeOUDACL(raw)
	if err != nil {
		return snapshot, err
	}
	// An OU that is itself an advertised naming-context head has no parent
	// object in that partition. The reference uses only its own deny ACE.
	actualDN, err := parseIdentityDN(before.DistinguishedName)
	if err != nil {
		return snapshot, err
	}
	partitionDN, err := parseIdentityDN(object.Partition)
	if err != nil {
		return snapshot, err
	}
	if sameIdentityDN(actualDN, partitionDN) {
		return ouProtectionSnapshot{raw: raw, acl: acl}, nil
	}
	// Resolve the actual observed parent under the already selected NC.
	parts, err := splitIdentityDN(before.DistinguishedName, ',')
	if err != nil || len(parts) < 2 {
		return snapshot, ErrIdentityScope
	}
	parentIdentity, err := IdentityByDN(strings.Join(parts[1:], ","))
	if err != nil {
		return snapshot, err
	}
	parent, err := resolveIdentitySession(ctx, session, config, root, parentIdentity, ResolveIdentityOptions{Partition: object.Partition, Properties: []string{"objectGUID"}})
	if err != nil {
		return snapshot, errors.Join(ErrOUProtection, err)
	}
	parentBefore, err := session.readOUDACL(ctx, parent.Object.DistinguishedName)
	result.Steps = append(result.Steps, OUProtectionStep{TargetDN: parentBefore.DistinguishedName, Before: &parentBefore})
	if err != nil {
		return snapshot, errors.Join(ErrOUProtection, err)
	}
	parentRaw, parentGUID, err := ouDescriptor(parentBefore)
	if err != nil {
		return snapshot, err
	}
	expectedValue, err := parent.Object.Values("objectGUID").Single()
	if err != nil {
		return snapshot, err
	}
	expectedGUID, err := expectedValue.GUID()
	if err != nil || *parentGUID != expectedGUID {
		return snapshot, errors.Join(ErrInvalidResult, err)
	}
	result.Steps[1].TargetGUID = parentGUID
	parentACL, err := decodeOUDACL(parentRaw)
	if err != nil {
		return snapshot, err
	}

	return ouProtectionSnapshot{raw: raw, parentRaw: parentRaw, acl: acl, parentACL: parentACL, parentDN: parentBefore.DistinguishedName}, nil
}

func changeOUProtection(ctx context.Context, directory ldapWriteSession, root RootDSE, config Config, object *ObjectMutationResult, protect bool, options ObjectMutationOptions, result *OUProtectionResult) error {
	session, ok := directory.(ouProtectionSession)
	if !ok {
		return ErrUnsupported
	}
	if !slices.Contains(root.SupportedControls, ouSDFlagsControl) {
		return ErrObjectControlUnsupported
	}
	// A single-object version cannot guard the parent's ACL. Reject this
	// combination rather than silently weakening the caller's precondition.
	if options.ExpectedVersion != nil && protect {
		return ErrObjectControlUnsupported
	}
	snapshot, err := prepareOUProtection(ctx, session, root, config, object, result)
	if err != nil {
		return err
	}
	raw, parentRaw, acl := snapshot.raw, snapshot.parentRaw, snapshot.acl
	leftBefore, rightBefore := ouACLProtection(acl, ouObjectProtectionMask), snapshot.parentProtection()
	if !protect && leftBefore != nil && rightBefore != nil && !(*leftBefore && *rightBefore) {
		if options.ExpectedVersion != nil {
			// A read-only no-op cannot enforce a server-side version assertion.
			return ErrObjectControlUnsupported
		}
		for i := range result.Steps {
			result.Steps[i].After = result.Steps[i].Before
			result.Steps[i].Verified = true
		}
		value := false
		result.ProtectedFromAccidentalDeletion = &value
		return nil
	}
	if protect {
		// Match the reference's parent-first order. Record the parent step
		// before the OU step so the returned order reflects actual dispatch.
		objectStep := 0
		if snapshot.parentDN != "" {
			result.Steps[0], result.Steps[1] = result.Steps[1], result.Steps[0]
			if err := writeOUProtectionStep(ctx, session, root, config, options, &result.Steps[0], parentRaw, ouParentProtectionMask, true); err != nil {
				return err
			}
			objectStep = 1
		}
		if err := writeOUProtectionStep(ctx, session, root, config, options, &result.Steps[objectStep], raw, ouObjectProtectionMask, true); err != nil {
			return err
		}
		if snapshot.parentDN != "" {
			actualParts, err := splitIdentityDN(result.Steps[objectStep].After.DistinguishedName, ',')
			if err != nil || len(actualParts) < 2 || !strings.EqualFold(strings.Join(actualParts[1:], ","), snapshot.parentDN) {
				return ErrOUProtection
			}
		}
		state := true
		result.ProtectedFromAccidentalDeletion = &state
		return nil
	}
	if err := writeOUProtectionStep(ctx, session, root, config, options, &result.Steps[0], raw, ouObjectProtectionMask, false); err != nil {
		return err
	}
	// Never write the parent's ACL while disabling. Its observation is still
	// relevant to the reference property's conjunction.
	if snapshot.parentDN != "" {
		result.Steps[1].After = result.Steps[1].Before
		result.Steps[1].Verified = true
	}
	if result.Steps[0].After != nil {
		if after, _, err := ouDescriptor(*result.Steps[0].After); err == nil {
			acl, err = decodeOUDACL(after)
			if err != nil {
				return err
			}
		}
	}
	left, right := ouACLProtection(acl, ouObjectProtectionMask), snapshot.parentProtection()
	if left != nil && right != nil {
		value := *left && *right
		result.ProtectedFromAccidentalDeletion = &value
	}
	if result.ProtectedFromAccidentalDeletion == nil || *result.ProtectedFromAccidentalDeletion {
		return ErrOUProtection
	}
	return nil
}

func (snapshot ouProtectionSnapshot) parentProtection() *bool {
	if snapshot.parentDN == "" {
		value := true
		return &value
	}
	return ouACLProtection(snapshot.parentACL, ouParentProtectionMask)
}

func writeOUProtectionStep(ctx context.Context, session ouProtectionSession, root RootDSE, config Config, options ObjectMutationOptions, step *OUProtectionStep, raw []byte, mask uint32, protect bool) error {
	updated, changed, err := session.editOUDACL(raw, mask, protect)
	if err != nil {
		return err
	}
	step.Changed = changed
	if !changed {
		if options.ExpectedVersion != nil {
			return ErrObjectControlUnsupported
		}
		step.After = step.Before
		acl, err := decodeOUDACL(raw)
		if err != nil {
			return err
		}
		state := ouACLProtection(acl, mask)
		if state == nil || *state != protect {
			return ErrOUProtection
		}
		step.Verified = true
		return nil
	}
	controls, err := objectWriteControls(root, config.Endpoint, options, *step.TargetGUID, false)
	if err != nil {
		return err
	}
	controls = append(controls, ldapWriteControl{oid: ouSDFlagsControl, critical: true, value: ouDACLControlValue})
	write := ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*step.TargetGUID), modifications: []ldapAttributeModification{{operation: 2, attribute: "nTSecurityDescriptor", values: [][]byte{updated}}}, controls: controls}
	var result ObjectMutationResult
	err = submitObjectWrite(ctx, session, write, false, &result)
	step.State = result.State
	if err != nil {
		return errors.Join(ErrOUProtection, err)
	}
	after, err := session.readOUDACL(ctx, write.dn)
	step.After = &after
	if err != nil {
		return errors.Join(ErrOUProtection, err)
	}
	afterRaw, afterGUID, err := ouDescriptor(after)
	if err != nil || *afterGUID != *step.TargetGUID {
		return errors.Join(ErrOUProtection, ErrInvalidResult, err)
	}
	actual, err := decodeOUDACL(afterRaw)
	if err != nil {
		return err
	}
	state := ouACLProtection(actual, mask)
	if state == nil || *state != protect {
		return ErrOUProtection
	}
	// The server may canonicalize a DACL. Every unrelated original ACE must
	// nevertheless survive exactly; don't claim preservation from state alone.
	expected, err := decodeOUDACL(updated)
	if err != nil {
		return err
	}
	remaining := make(map[string]int, len(actual.aces))
	for _, ace := range actual.aces {
		remaining[string(ace)]++
	}
	for _, ace := range expected.aces {
		if remaining[string(ace)] == 0 {
			return ErrOUProtection
		}
		remaining[string(ace)]--
	}
	step.Verified = true
	return nil
}

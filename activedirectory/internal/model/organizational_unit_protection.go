package model

import (
	"context"
	"errors"
	"slices"
	"strings"
)

type InternalOuProtectionSession interface {
	InternalLdapWriteSession
	InternalReadOUDACL(context.Context, string) (Object, error)
	InternalEditOUDACL([]byte, uint32, bool) ([]byte, bool, error)
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

func InternalOuDescriptor(object Object) ([]byte, *GUID, error) {
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

type InternalOuProtectionSnapshot struct {
	InternalRaw, InternalParentRaw []byte
	InternalAcl, InternalParentACL InternalOuDACL
	InternalParentDN               string
}

func InternalPrepareOUProtection(
	ctx context.Context,
	session InternalOuProtectionSession,
	root RootDSE,
	config Config,
	object *ObjectMutationResult,
	result *OUProtectionResult,
) (InternalOuProtectionSnapshot, error) {
	var snapshot InternalOuProtectionSnapshot
	before, err := session.InternalReadOUDACL(ctx, InternalObjectGUIDTarget(*object.TargetGUID))
	result.Steps = append(
		result.Steps,
		OUProtectionStep{TargetDN: before.DistinguishedName, Before: &before},
	)
	if err != nil {
		return snapshot, errors.Join(ErrOUProtection, err)
	}
	raw, guid, err := InternalOuDescriptor(before)
	if err != nil || *guid != *object.TargetGUID {
		return snapshot, errors.Join(ErrOUProtection, ErrInvalidResult, err)
	}
	result.Steps[0].TargetGUID = guid
	acl, err := InternalDecodeOUDACL(raw)
	if err != nil {
		return snapshot, err
	}
	// An OU that is itself an advertised naming-context head has no parent
	// object in that partition. The reference uses only its own deny ACE.
	actualDN, err := InternalParseIdentityDN(before.DistinguishedName)
	if err != nil {
		return snapshot, err
	}
	partitionDN, err := InternalParseIdentityDN(object.Partition)
	if err != nil {
		return snapshot, err
	}
	if InternalSameIdentityDN(actualDN, partitionDN) {
		return InternalOuProtectionSnapshot{InternalRaw: raw, InternalAcl: acl}, nil
	}
	// Resolve the actual observed parent under the already selected NC.
	parts, err := InternalSplitIdentityDN(before.DistinguishedName, ',')
	if err != nil || len(parts) < 2 {
		return snapshot, ErrIdentityScope
	}
	parentIdentity, err := IdentityByDN(strings.Join(parts[1:], ","))
	if err != nil {
		return snapshot, err
	}
	parent, err := InternalResolveIdentitySession(
		ctx,
		session,
		config,
		root,
		parentIdentity,
		ResolveIdentityOptions{Partition: object.Partition, Properties: []string{"objectGUID"}},
	)
	if err != nil {
		return snapshot, errors.Join(ErrOUProtection, err)
	}
	parentBefore, err := session.InternalReadOUDACL(ctx, parent.Object.DistinguishedName)
	result.Steps = append(
		result.Steps,
		OUProtectionStep{TargetDN: parentBefore.DistinguishedName, Before: &parentBefore},
	)
	if err != nil {
		return snapshot, errors.Join(ErrOUProtection, err)
	}
	parentRaw, parentGUID, err := InternalOuDescriptor(parentBefore)
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
	parentACL, err := InternalDecodeOUDACL(parentRaw)
	if err != nil {
		return snapshot, err
	}

	return InternalOuProtectionSnapshot{
		InternalRaw:       raw,
		InternalParentRaw: parentRaw,
		InternalAcl:       acl,
		InternalParentACL: parentACL,
		InternalParentDN:  parentBefore.DistinguishedName,
	}, nil
}

func InternalChangeOUProtection(
	ctx context.Context,
	directory InternalLdapWriteSession,
	root RootDSE,
	config Config,
	object *ObjectMutationResult,
	protect bool,
	options ObjectMutationOptions,
	result *OUProtectionResult,
) error {
	session, ok := directory.(InternalOuProtectionSession)
	if !ok {
		return ErrUnsupported
	}
	if !slices.Contains(root.SupportedControls, InternalOuSDFlagsControl) {
		return ErrObjectControlUnsupported
	}
	// A single-object version cannot guard the parent's ACL. Reject this
	// combination rather than silently weakening the caller's precondition.
	if options.ExpectedVersion != nil && protect {
		return ErrObjectControlUnsupported
	}
	snapshot, err := InternalPrepareOUProtection(ctx, session, root, config, object, result)
	if err != nil {
		return err
	}
	raw, parentRaw, acl := snapshot.InternalRaw, snapshot.InternalParentRaw, snapshot.InternalAcl
	leftBefore, rightBefore := InternalOuACLProtection(
		acl,
		InternalOuObjectProtectionMask,
	), snapshot.InternalParentProtection()
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
		if snapshot.InternalParentDN != "" {
			result.Steps[0], result.Steps[1] = result.Steps[1], result.Steps[0]
			if err := InternalWriteOUProtectionStep(
				ctx,
				session,
				root,
				config,
				options,
				&result.Steps[0],
				parentRaw,
				InternalOuParentProtectionMask,
				true,
			); err != nil {
				return err
			}
			objectStep = 1
		}
		if err := InternalWriteOUProtectionStep(
			ctx,
			session,
			root,
			config,
			options,
			&result.Steps[objectStep],
			raw,
			InternalOuObjectProtectionMask,
			true,
		); err != nil {
			return err
		}
		if snapshot.InternalParentDN != "" {
			actualParts, err := InternalSplitIdentityDN(
				result.Steps[objectStep].After.DistinguishedName,
				',',
			)
			if err != nil || len(actualParts) < 2 ||
				!strings.EqualFold(strings.Join(actualParts[1:], ","), snapshot.InternalParentDN) {
				return ErrOUProtection
			}
		}
		state := true
		result.ProtectedFromAccidentalDeletion = &state
		return nil
	}
	if err := InternalWriteOUProtectionStep(
		ctx,
		session,
		root,
		config,
		options,
		&result.Steps[0],
		raw,
		InternalOuObjectProtectionMask,
		false,
	); err != nil {
		return err
	}
	// Never write the parent's ACL while disabling. Its observation is still
	// relevant to the reference property's conjunction.
	if snapshot.InternalParentDN != "" {
		result.Steps[1].After = result.Steps[1].Before
		result.Steps[1].Verified = true
	}
	if result.Steps[0].After != nil {
		if after, _, err := InternalOuDescriptor(*result.Steps[0].After); err == nil {
			acl, err = InternalDecodeOUDACL(after)
			if err != nil {
				return err
			}
		}
	}
	left, right := InternalOuACLProtection(
		acl,
		InternalOuObjectProtectionMask,
	), snapshot.InternalParentProtection()
	if left != nil && right != nil {
		value := *left && *right
		result.ProtectedFromAccidentalDeletion = &value
	}
	if result.ProtectedFromAccidentalDeletion == nil || *result.ProtectedFromAccidentalDeletion {
		return ErrOUProtection
	}
	return nil
}

func (snapshot InternalOuProtectionSnapshot) InternalParentProtection() *bool {
	if snapshot.InternalParentDN == "" {
		value := true
		return &value
	}
	return InternalOuACLProtection(snapshot.InternalParentACL, InternalOuParentProtectionMask)
}

func InternalWriteOUProtectionStep(
	ctx context.Context,
	session InternalOuProtectionSession,
	root RootDSE,
	config Config,
	options ObjectMutationOptions,
	step *OUProtectionStep,
	raw []byte,
	mask uint32,
	protect bool,
) error {
	updated, changed, err := session.InternalEditOUDACL(raw, mask, protect)
	if err != nil {
		return err
	}
	step.Changed = changed
	if !changed {
		if options.ExpectedVersion != nil {
			return ErrObjectControlUnsupported
		}
		step.After = step.Before
		acl, err := InternalDecodeOUDACL(raw)
		if err != nil {
			return err
		}
		state := InternalOuACLProtection(acl, mask)
		if state == nil || *state != protect {
			return ErrOUProtection
		}
		step.Verified = true
		return nil
	}
	controls, err := InternalObjectWriteControls(
		root,
		config.Endpoint,
		options,
		*step.TargetGUID,
		false,
	)
	if err != nil {
		return err
	}
	controls = append(
		controls,
		InternalLdapWriteControl{
			InternalOid:      InternalOuSDFlagsControl,
			InternalCritical: true,
			InternalValue:    InternalOuDACLControlValue,
		},
	)
	write := InternalLdapWriteRequest{
		InternalOperation: InternalLdapWriteModify,
		InternalDn:        InternalObjectGUIDTarget(*step.TargetGUID),
		InternalModifications: []InternalLdapAttributeModification{
			{
				InternalOperation: 2,
				InternalAttribute: "nTSecurityDescriptor",
				InternalValues:    [][]byte{updated},
			},
		},
		InternalControls: controls,
	}
	var result ObjectMutationResult
	err = InternalSubmitObjectWrite(ctx, session, write, false, &result)
	step.State = result.State
	if err != nil {
		return errors.Join(ErrOUProtection, err)
	}
	after, err := session.InternalReadOUDACL(ctx, write.InternalDn)
	step.After = &after
	if err != nil {
		return errors.Join(ErrOUProtection, err)
	}
	afterRaw, afterGUID, err := InternalOuDescriptor(after)
	if err != nil || *afterGUID != *step.TargetGUID {
		return errors.Join(ErrOUProtection, ErrInvalidResult, err)
	}
	actual, err := InternalDecodeOUDACL(afterRaw)
	if err != nil {
		return err
	}
	state := InternalOuACLProtection(actual, mask)
	if state == nil || *state != protect {
		return ErrOUProtection
	}
	// The server may canonicalize a DACL. Every unrelated original ACE must
	// nevertheless survive exactly; don't claim preservation from state alone.
	expected, err := InternalDecodeOUDACL(updated)
	if err != nil {
		return err
	}
	remaining := make(map[string]int, len(actual.InternalAces))
	for _, ace := range actual.InternalAces {
		remaining[string(ace)]++
	}
	for _, ace := range expected.InternalAces {
		if remaining[string(ace)] == 0 {
			return ErrOUProtection
		}
		remaining[string(ace)]--
	}
	step.Verified = true
	return nil
}

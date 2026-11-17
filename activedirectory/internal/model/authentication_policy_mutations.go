package model

import (
	"context"
	"errors"
	"slices"
	"strings"
)

type CreateAuthenticationPolicyRequest struct {
	Name       string
	Properties AuthenticationPolicyProperties
	Attributes map[string][]RawValue
	// Nil leaves the schema/default ACL unchanged; true/false requests the
	// existing explicit protection ACL workflow after the Add is verified.
	ProtectedFromAccidentalDeletion *bool
	Options                         ObjectMutationOptions
}

type UpdateAuthenticationPolicyRequest struct {
	Identity                        Identity
	Properties                      AuthenticationPolicyProperties
	Changes                         []AttributeChange
	ProtectedFromAccidentalDeletion *bool
	Options                         ObjectMutationOptions
}

type DeleteAuthenticationPolicyRequest struct {
	Identity Identity
	Options  ObjectMutationOptions
}

// Protection reuses the shared ACL workflow and its per-object outcomes.
// Attribute and parent/object protection writes are separate requests, never a
// transaction. An earlier accepted request is retained after any later error.
type AuthenticationPolicyMutationResult struct {
	Mutation   ObjectMutationResult
	Policy     *AuthenticationPolicy
	Protection OUProtectionResult
}

func InternalAuthenticationPolicyWritePrerequisites(
	ctx context.Context,
	session InternalDirectorySession,
	root RootDSE,
	mods []InternalLdapAttributeModification,
) error {
	if _, err := InternalAuthenticationPolicyContainer(root); err != nil {
		return err
	}
	if root.DomainFunctionality == nil || *root.DomainFunctionality < 6 ||
		root.SchemaNamingContext == nil ||
		root.DSServiceName == nil ||
		root.IsSynchronized == nil ||
		!*root.IsSynchronized ||
		root.Capabilities().Has("1.2.840.113556.1.4.1920") {
		return ErrAuthenticationPolicyPrerequisite
	}
	attrs, err := session.InternalBaseObject(
		ctx,
		*root.DSServiceName,
		[]string{"msDS-isRODC", "objectClass"},
	)
	if err != nil {
		return err
	}
	d := InternalRootDSEDecoder{InternalAttributes: attrs}
	readOnly := InternalDecodeScalar(&d, "msDS-isRODC", InternalParseLDAPBool)
	classes := d.InternalTexts("objectClass")
	if readOnly == nil || *readOnly ||
		!slices.ContainsFunc(
			classes,
			func(value string) bool { return strings.EqualFold(value, "nTDSDSA") },
		) ||
		len(d.InternalErrors) != 0 {
		return errors.Join(ErrAuthenticationPolicyPrerequisite, errors.Join(d.InternalErrors...))
	}
	minimum := uint32(69)
	for _, mod := range mods {
		switch strings.ToLower(mod.InternalAttribute) {
		case "msds-strongntlmpolicy",
			"msds-userallowedntlmnetworkauthentication",
			"msds-serviceallowedntlmnetworkauthentication":
			minimum = 85
		}
	}
	attrs, err = session.InternalBaseObject(
		ctx,
		*root.SchemaNamingContext,
		[]string{"objectVersion"},
	)
	if err != nil {
		return err
	}
	d = InternalRootDSEDecoder{InternalAttributes: attrs}
	version := InternalDecodeScalar(&d, "objectVersion", InternalParseUint32)
	if version == nil || *version < minimum || len(d.InternalErrors) != 0 ||
		(minimum == 85 && *root.DomainControllerFunctionality < 7) {
		return errors.Join(ErrAuthenticationPolicyPrerequisite, errors.Join(d.InternalErrors...))
	}
	return nil
}

func InternalFinishAuthenticationPolicyMutation(
	result AuthenticationPolicyMutationResult,
	err error,
) (AuthenticationPolicyMutationResult, error) {
	observed := result.Mutation.After
	if observed == nil && result.Mutation.State == ObjectWriteNotAttempted &&
		result.Protection.ProtectedFromAccidentalDeletion != nil {
		observed = result.Mutation.Before
	}
	if observed != nil {
		policy, decodeErr := InternalDecodeAuthenticationPolicy(*observed)
		policy.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.Policy = &policy
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

func InternalAuthenticationProtectionRequested(properties []string) bool {
	return slices.ContainsFunc(
		properties,
		func(name string) bool { return strings.EqualFold(name, "ProtectedFromAccidentalDeletion") },
	)
}

func InternalAuthenticationProtectionAvailable(
	session InternalLdapWriteSession,
	root RootDSE,
	requested *bool,
	properties []string,
) error {
	if requested == nil && !InternalAuthenticationProtectionRequested(properties) {
		return nil
	}
	if _, ok := session.(InternalOuProtectionSession); !ok {
		return ErrUnsupported
	}
	if !slices.Contains(root.SupportedControls, InternalDirectorySDFlagsControl) {
		return ErrObjectControlUnsupported
	}
	return nil
}

func InternalAuthenticationPolicyProtection(
	ctx context.Context,
	session InternalLdapWriteSession,
	root RootDSE,
	config Config,
	mutation *ObjectMutationResult,
	options ObjectMutationOptions,
	requested *bool,
	properties []string,
	result *OUProtectionResult,
) error {
	if requested != nil {
		return InternalChangeOUProtection(
			ctx,
			session,
			root,
			config,
			mutation,
			*requested,
			options,
			result,
		)
	}
	if !InternalAuthenticationProtectionRequested(properties) {
		return nil
	}
	observed, err := InternalReadOUProtection(
		ctx,
		session,
		root,
		config,
		OrganizationalUnit{DistinguishedName: mutation.TargetDN, GUID: mutation.TargetGUID},
		mutation.Partition,
	)
	*result = observed
	return err
}

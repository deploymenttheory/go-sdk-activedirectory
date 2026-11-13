package activedirectory

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

func (c *Client) authenticationPolicyOptions(ctx context.Context, options ObjectMutationOptions) (ObjectMutationOptions, RootDSE, error) {
	root, err := c.RootDSE(ctx, RootDSEOptions{})
	if err != nil {
		return options, root, err
	}
	if _, err := authenticationPolicyContainer(root); err != nil {
		return options, root, err
	}
	if options.Partition != "" && !sameAuthenticationDN(options.Partition, *root.ConfigurationNamingContext) {
		return options, root, ErrIdentityScope
	}
	options.Partition = *root.ConfigurationNamingContext
	options.Properties = authenticationPolicyProperties(options.Properties)
	return options, root, nil
}

func authenticationPolicyWritePrerequisites(ctx context.Context, session directorySession, root RootDSE, mods []ldapAttributeModification) error {
	if _, err := authenticationPolicyContainer(root); err != nil {
		return err
	}
	if root.DomainFunctionality == nil || *root.DomainFunctionality < 6 || root.SchemaNamingContext == nil || root.DSServiceName == nil || root.IsSynchronized == nil || !*root.IsSynchronized || root.Capabilities().Has("1.2.840.113556.1.4.1920") {
		return ErrAuthenticationPolicyPrerequisite
	}
	attrs, err := session.baseObject(ctx, *root.DSServiceName, []string{"msDS-isRODC", "objectClass"})
	if err != nil {
		return err
	}
	d := rootDSEDecoder{attributes: attrs}
	readOnly := decodeScalar(&d, "msDS-isRODC", parseLDAPBool)
	classes := d.texts("objectClass")
	if readOnly == nil || *readOnly || !slices.ContainsFunc(classes, func(value string) bool { return strings.EqualFold(value, "nTDSDSA") }) || len(d.errors) != 0 {
		return errors.Join(ErrAuthenticationPolicyPrerequisite, errors.Join(d.errors...))
	}
	minimum := uint32(69)
	for _, mod := range mods {
		switch strings.ToLower(mod.attribute) {
		case "msds-strongntlmpolicy", "msds-userallowedntlmnetworkauthentication", "msds-serviceallowedntlmnetworkauthentication":
			minimum = 85
		}
	}
	attrs, err = session.baseObject(ctx, *root.SchemaNamingContext, []string{"objectVersion"})
	if err != nil {
		return err
	}
	d = rootDSEDecoder{attributes: attrs}
	version := decodeScalar(&d, "objectVersion", parseUint32)
	if version == nil || *version < minimum || len(d.errors) != 0 || (minimum == 85 && *root.DomainControllerFunctionality < 7) {
		return errors.Join(ErrAuthenticationPolicyPrerequisite, errors.Join(d.errors...))
	}
	return nil
}

func (c *Client) CreateAuthenticationPolicy(ctx context.Context, request CreateAuthenticationPolicyRequest) (AuthenticationPolicyMutationResult, error) {
	var result AuthenticationPolicyMutationResult
	if request.Name == "" || !validDirectoryText(request.Name) {
		return result, ErrInvalidAuthenticationPolicy
	}
	if request.Options.ExpectedVersion != nil {
		return result, ErrObjectControlUnsupported
	}
	var raw []AttributeChange
	for name, values := range request.Attributes {
		raw = append(raw, AttributeChange{Attribute: name, Kind: AttributeSet, Values: values})
	}
	properties := request.Properties
	if properties.Enforced == nil && !slices.ContainsFunc(raw, func(change AttributeChange) bool {
		return strings.EqualFold(change.Attribute, "msDS-AuthNPolicyEnforced")
	}) {
		value := false
		properties.Enforced = &value
	}
	mods, err := authenticationPolicyChanges(properties, raw)
	if err != nil {
		return result, err
	}
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	options, root, err := c.authenticationPolicyOptions(ctx, request.Options)
	if err != nil {
		return result, err
	}
	container, _ := authenticationPolicyContainer(root)
	parent, err := IdentityByDN(container)
	if err != nil {
		return result, err
	}
	if err := validateObjectOptions(parent, options); err != nil {
		return result, err
	}
	result.Mutation, err = c.objectMutation(ctx, parent, options, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		if err := authenticationPolicyWritePrerequisites(ctx, session, root, mods); err != nil {
			return err
		}
		if err := authenticationProtectionAvailable(session, root, request.ProtectedFromAccidentalDeletion, request.Options.Properties); err != nil {
			return err
		}
		currentContainer, _ := authenticationPolicyContainer(root)
		if !sameAuthenticationDN(observed.Object.DistinguishedName, currentContainer) {
			return ErrIdentityScope
		}
		classes, _ := observed.Object.Attribute("objectClass")
		if !slices.ContainsFunc(classes, func(value []byte) bool { return strings.EqualFold(string(value), "msDS-AuthNPolicies") }) {
			return ErrNotAuthenticationPolicy
		}
		naming, err := objectClassNamingAttribute(ctx, session, root, "msDS-AuthNPolicy")
		if err != nil {
			return err
		}
		if !strings.EqualFold(naming, "cn") {
			return ErrInvalidResult
		}
		for _, mod := range mods {
			if strings.EqualFold(mod.attribute, naming) {
				return ErrInvalidAuthenticationPolicy
			}
		}
		mutation.Before, mutation.TargetGUID = nil, nil
		mutation.TargetDN = naming + "=" + escapeObjectName(request.Name) + "," + observed.Object.DistinguishedName
		writes := append(slices.Clone(mods), ldapAttributeModification{attribute: "objectClass", values: [][]byte{[]byte("msDS-AuthNPolicy")}}, ldapAttributeModification{attribute: naming, values: [][]byte{[]byte(request.Name)}})
		for i := range writes {
			writes[i].operation = 0
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteAdd, dn: mutation.TargetDN, modifications: writes}, false, mutation); err != nil {
			return err
		}
		identity, err := IdentityByDN(mutation.TargetDN)
		if err != nil {
			return errors.Join(ErrObjectReadback, err)
		}
		if err := observeObjectWrite(ctx, session, c.config, root, identity, mutation, objectWriteProperties(options, writes), false); err != nil {
			return err
		}
		if err := verifyObjectWrite(mutation, writes, request.Name); err != nil {
			return err
		}
		if err := authenticationPolicyScope(root, *mutation.After); err != nil {
			return err
		}
		return authenticationPolicyProtection(ctx, session, root, c.config, mutation, options, request.ProtectedFromAccidentalDeletion, request.Options.Properties, &result.Protection)
	})
	return finishAuthenticationPolicyMutation(result, err)
}

func (c *Client) UpdateAuthenticationPolicy(ctx context.Context, request UpdateAuthenticationPolicyRequest) (AuthenticationPolicyMutationResult, error) {
	var result AuthenticationPolicyMutationResult
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	mods, err := authenticationPolicyChanges(request.Properties, request.Changes)
	if err != nil {
		return result, err
	}
	if len(mods) == 0 && request.ProtectedFromAccidentalDeletion == nil {
		return result, ErrInvalidAuthenticationPolicy
	}
	if len(mods) != 0 && request.ProtectedFromAccidentalDeletion != nil && request.Options.ExpectedVersion != nil {
		return result, ErrObjectControlUnsupported
	}
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	options, _, err := c.authenticationPolicyOptions(ctx, request.Options)
	if err != nil {
		return result, err
	}
	result.Mutation, err = c.objectMutationIdentity(ctx, request.Identity, options, ResolveIdentityOptions{Properties: options.Properties}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		if err := authenticationPolicyScope(root, *observed.Object); err != nil {
			return err
		}
		if err := authenticationPolicyWritePrerequisites(ctx, session, root, mods); err != nil {
			return err
		}
		if err := authenticationProtectionAvailable(session, root, request.ProtectedFromAccidentalDeletion, request.Options.Properties); err != nil {
			return err
		}
		if len(mods) != 0 {
			controls, err := objectWriteControls(root, c.config.Endpoint, options, *mutation.TargetGUID, false)
			if err != nil {
				return err
			}
			if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*mutation.TargetGUID), modifications: mods, controls: controls}, false, mutation); err != nil {
				return err
			}
			if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*mutation.TargetGUID), mutation, objectWriteProperties(options, mods), false); err != nil {
				return err
			}
			if err := verifyObjectWrite(mutation, mods, ""); err != nil {
				return err
			}
		}
		return authenticationPolicyProtection(ctx, session, root, c.config, mutation, options, request.ProtectedFromAccidentalDeletion, request.Options.Properties, &result.Protection)
	})
	return finishAuthenticationPolicyMutation(result, err)
}

func finishAuthenticationPolicyMutation(result AuthenticationPolicyMutationResult, err error) (AuthenticationPolicyMutationResult, error) {
	observed := result.Mutation.After
	if observed == nil && result.Mutation.State == ObjectWriteNotAttempted && result.Protection.ProtectedFromAccidentalDeletion != nil {
		observed = result.Mutation.Before
	}
	if observed != nil {
		policy, decodeErr := decodeAuthenticationPolicy(*observed)
		policy.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.Policy = &policy
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

func authenticationProtectionRequested(properties []string) bool {
	return slices.ContainsFunc(properties, func(name string) bool { return strings.EqualFold(name, "ProtectedFromAccidentalDeletion") })
}

func authenticationProtectionAvailable(session ldapWriteSession, root RootDSE, requested *bool, properties []string) error {
	if requested == nil && !authenticationProtectionRequested(properties) {
		return nil
	}
	if _, ok := session.(ouProtectionSession); !ok {
		return ErrUnsupported
	}
	if !slices.Contains(root.SupportedControls, directorySDFlagsControl) {
		return ErrObjectControlUnsupported
	}
	return nil
}

func authenticationPolicyProtection(ctx context.Context, session ldapWriteSession, root RootDSE, config Config, mutation *ObjectMutationResult, options ObjectMutationOptions, requested *bool, properties []string, result *OUProtectionResult) error {
	if requested != nil {
		return changeOUProtection(ctx, session, root, config, mutation, *requested, options, result)
	}
	if !authenticationProtectionRequested(properties) {
		return nil
	}
	observed, err := readOUProtection(ctx, session, root, config, OrganizationalUnit{DistinguishedName: mutation.TargetDN, GUID: mutation.TargetGUID}, mutation.Partition)
	*result = observed
	return err
}

// DeleteAuthenticationPolicy is a leaf delete. It never disables protection,
// edits referencing accounts/silos, or retries a server reference constraint.
func (c *Client) DeleteAuthenticationPolicy(ctx context.Context, request DeleteAuthenticationPolicyRequest) (ObjectMutationResult, error) {
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return ObjectMutationResult{}, err
	}
	if c == nil || c.session == nil {
		return ObjectMutationResult{}, ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	options, _, err := c.authenticationPolicyOptions(ctx, request.Options)
	if err != nil {
		return ObjectMutationResult{}, err
	}
	return c.objectMutation(ctx, request.Identity, options, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		if err := authenticationPolicyScope(root, *observed.Object); err != nil {
			return err
		}
		if err := authenticationPolicyWritePrerequisites(ctx, session, root, nil); err != nil {
			return err
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, options, *mutation.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteDelete, dn: objectGUIDTarget(*mutation.TargetGUID), controls: controls}, false, mutation); err != nil {
			return err
		}
		return observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*mutation.TargetGUID), mutation, []string{"objectGUID"}, true)
	})
}

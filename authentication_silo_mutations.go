package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strings"
)

type AuthenticationPolicySiloProperties struct {
	Description *string
	Enforced    *bool
	// Nil omits; raw AttributeClear clears a reference. References accept DN/GUID.
	UserAuthenticationPolicy, ComputerAuthenticationPolicy, ServiceAuthenticationPolicy *Identity
}

type CreateAuthenticationPolicySiloRequest struct {
	Name                            string
	Properties                      AuthenticationPolicySiloProperties
	Attributes                      map[string][]RawValue
	ProtectedFromAccidentalDeletion *bool
	Options                         ObjectMutationOptions
}

type UpdateAuthenticationPolicySiloRequest struct {
	Identity                        Identity
	Properties                      AuthenticationPolicySiloProperties
	Changes                         []AttributeChange
	ProtectedFromAccidentalDeletion *bool
	Options                         ObjectMutationOptions
}

type DeleteAuthenticationPolicySiloRequest struct {
	Identity Identity
	Options  ObjectMutationOptions
}

type AuthenticationPolicySiloMutationResult struct {
	Mutation           ObjectMutationResult
	Silo               *AuthenticationPolicySilo
	PolicyObservations []IdentityResult
	Protection         OUProtectionResult
}

func siloPolicyIdentities(properties AuthenticationPolicySiloProperties) []struct {
	attribute string
	identity  *Identity
} {
	return []struct {
		attribute string
		identity  *Identity
	}{{"msDS-UserAuthNPolicy", properties.UserAuthenticationPolicy}, {"msDS-ComputerAuthNPolicy", properties.ComputerAuthenticationPolicy}, {"msDS-ServiceAuthNPolicy", properties.ServiceAuthenticationPolicy}}
}

func siloPolicyAttribute(name string) bool {
	switch strings.ToLower(name) {
	case "msds-userauthnpolicy", "msds-computerauthnpolicy", "msds-serviceauthnpolicy":
		return true
	}
	return false
}

func authenticationSiloChanges(properties AuthenticationPolicySiloProperties, raw []AttributeChange) ([]ldapAttributeModification, error) {
	changes := slices.Clone(raw)
	for _, change := range raw {
		switch strings.ToLower(change.Attribute) {
		case "ntsecuritydescriptor", "msds-authnpolicysilomembers", "msds-assignedauthnpolicysilobl", "msds-assignedauthnpolicy", "msds-assignedauthnpolicysilo":
			return nil, ErrInvalidAuthenticationSilo
		}
	}
	if properties.Description != nil {
		if !validDirectoryText(*properties.Description) {
			return nil, ErrInvalidAuthenticationSilo
		}
		changes = append(changes, authenticationSetting("description", *properties.Description))
	}
	if properties.Enforced != nil {
		value := "FALSE"
		if *properties.Enforced {
			value = "TRUE"
		}
		changes = append(changes, authenticationSetting("msDS-AuthNPolicySiloEnforced", value))
	}
	for _, reference := range siloPolicyIdentities(properties) {
		if reference.identity == nil {
			continue
		}
		if err := validateIdentityOperation(*reference.identity, ResolveIdentityOptions{}); err != nil {
			return nil, err
		}
		// The placeholder is replaced by a resolved canonical DN before dispatch.
		changes = append(changes, authenticationSetting(reference.attribute, "pending"))
	}
	if len(changes) == 0 {
		return nil, nil
	}
	mods, err := objectChanges(changes)
	if err != nil {
		return nil, err
	}
	for _, mod := range mods {
		if mod.operation == 1 && len(mod.values) == 0 {
			continue
		}
		if strings.EqualFold(mod.attribute, "msDS-AuthNPolicySiloEnforced") {
			if len(mod.values) != 1 {
				return nil, ErrInvalidAuthenticationSilo
			}
			if _, err := parseLDAPBool(string(mod.values[0])); err != nil {
				return nil, ErrInvalidAuthenticationSilo
			}
		}
		if siloPolicyAttribute(mod.attribute) && len(mod.values) != 1 {
			return nil, ErrInvalidAuthenticationSilo
		}
	}
	return mods, nil
}

func resolveSiloPolicies(ctx context.Context, session directorySession, config Config, root RootDSE, properties AuthenticationPolicySiloProperties, mods []ldapAttributeModification, result *AuthenticationPolicySiloMutationResult) error {
	for i := range mods {
		mod := &mods[i]
		if !siloPolicyAttribute(mod.attribute) || len(mod.values) == 0 {
			continue
		}
		var identity *Identity
		for _, reference := range siloPolicyIdentities(properties) {
			if strings.EqualFold(reference.attribute, mod.attribute) {
				identity = reference.identity
			}
		}
		if identity == nil {
			parsed, err := IdentityByDN(string(mod.values[0]))
			if err != nil {
				return err
			}
			identity = &parsed
		}
		observed, err := resolveIdentitySession(ctx, session, config, root, *identity, ResolveIdentityOptions{Partition: *root.ConfigurationNamingContext, Properties: authenticationPolicyProperties(nil)})
		result.PolicyObservations = append(result.PolicyObservations, observed)
		if err != nil {
			return err
		}
		if err := authenticationPolicyScope(root, *observed.Object); err != nil {
			return err
		}
		mod.values = [][]byte{[]byte(observed.Object.DistinguishedName)}
	}
	return nil
}

func (c *Client) authenticationSiloOptions(ctx context.Context, options ObjectMutationOptions) (ObjectMutationOptions, RootDSE, error) {
	resolved, root, err := c.authenticationPolicyOptions(ctx, options)
	resolved.Properties = authenticationSiloProperties(options.Properties)
	return resolved, root, err
}

func finishAuthenticationSiloMutation(result AuthenticationPolicySiloMutationResult, err error) (AuthenticationPolicySiloMutationResult, error) {
	object := result.Mutation.After
	if object == nil && result.Mutation.State == ObjectWriteNotAttempted && result.Protection.ProtectedFromAccidentalDeletion != nil {
		object = result.Mutation.Before
	}
	if object != nil {
		silo, decodeErr := decodeAuthenticationSilo(*object)
		silo.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.Silo = &silo
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

// CreateAuthenticationPolicySilo creates an audit-mode silo by default. Nil
// protection leaves the schema ACL unchanged, matching the module's default.
func (c *Client) CreateAuthenticationPolicySilo(ctx context.Context, request CreateAuthenticationPolicySiloRequest) (AuthenticationPolicySiloMutationResult, error) {
	var result AuthenticationPolicySiloMutationResult
	if request.Name == "" || !validDirectoryText(request.Name) {
		return result, ErrInvalidAuthenticationSilo
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
		return strings.EqualFold(change.Attribute, "msDS-AuthNPolicySiloEnforced")
	}) {
		value := false
		properties.Enforced = &value
	}
	mods, err := authenticationSiloChanges(properties, raw)
	if err != nil {
		return result, err
	}
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	options, root, err := c.authenticationSiloOptions(ctx, request.Options)
	if err != nil {
		return result, err
	}
	container, _ := authenticationSiloContainer(root)
	parent, err := IdentityByDN(container)
	if err != nil {
		return result, err
	}
	if err := validateObjectOptions(parent, options); err != nil {
		return result, err
	}
	result.Mutation, err = c.objectMutation(ctx, parent, options, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		if err := authenticationPolicyWritePrerequisites(ctx, session, root, nil); err != nil {
			return err
		}
		if err := authenticationProtectionAvailable(session, root, request.ProtectedFromAccidentalDeletion, request.Options.Properties); err != nil {
			return err
		}
		currentContainer, _ := authenticationSiloContainer(root)
		classes, _ := observed.Object.Attribute("objectClass")
		if !sameAuthenticationDN(observed.Object.DistinguishedName, currentContainer) || !slices.ContainsFunc(classes, func(value []byte) bool { return strings.EqualFold(string(value), "msDS-AuthNPolicySilos") }) {
			return ErrNotAuthenticationSilo
		}
		naming, err := objectClassNamingAttribute(ctx, session, root, "msDS-AuthNPolicySilo")
		if err != nil {
			return err
		}
		if !strings.EqualFold(naming, "cn") {
			return ErrInvalidResult
		}
		for _, mod := range mods {
			if strings.EqualFold(mod.attribute, naming) {
				return ErrInvalidAuthenticationSilo
			}
		}
		if err := resolveSiloPolicies(ctx, session, c.config, root, properties, mods, &result); err != nil {
			return err
		}
		mutation.Before, mutation.TargetGUID = nil, nil
		mutation.TargetDN = naming + "=" + escapeObjectName(request.Name) + "," + observed.Object.DistinguishedName
		writes := append(slices.Clone(mods), ldapAttributeModification{attribute: "objectClass", values: [][]byte{[]byte("msDS-AuthNPolicySilo")}}, ldapAttributeModification{attribute: naming, values: [][]byte{[]byte(request.Name)}})
		for i := range writes {
			writes[i].operation = 0
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteAdd, dn: mutation.TargetDN, modifications: writes}, false, mutation); err != nil {
			return err
		}
		identity, _ := IdentityByDN(mutation.TargetDN)
		if err := observeObjectWrite(ctx, session, c.config, root, identity, mutation, objectWriteProperties(options, writes), false); err != nil {
			return err
		}
		if err := verifyAuthenticationSiloWrite(mutation, writes, request.Name); err != nil {
			return err
		}
		if err := authenticationSiloScope(root, *mutation.After); err != nil {
			return err
		}
		return authenticationPolicyProtection(ctx, session, root, c.config, mutation, options, request.ProtectedFromAccidentalDeletion, request.Options.Properties, &result.Protection)
	})
	return finishAuthenticationSiloMutation(result, err)
}

func verifyAuthenticationSiloWrite(mutation *ObjectMutationResult, mods []ldapAttributeModification, name string) error {
	ordinary := make([]ldapAttributeModification, 0, len(mods))
	for _, mod := range mods {
		if !siloPolicyAttribute(mod.attribute) || len(mod.values) == 0 {
			ordinary = append(ordinary, mod)
			continue
		}
		value, err := mutation.After.Values(mod.attribute).Single()
		if err != nil {
			return errors.Join(ErrObjectVerification, err)
		}
		matches := sameAuthenticationDN(string(value.Bytes()), string(mod.values[0]))
		if (mod.operation == 1 && matches) || (mod.operation != 1 && !matches) {
			return ErrObjectVerification
		}
	}
	return verifyObjectWrite(mutation, ordinary, name)
}

func (c *Client) UpdateAuthenticationPolicySilo(ctx context.Context, request UpdateAuthenticationPolicySiloRequest) (AuthenticationPolicySiloMutationResult, error) {
	var result AuthenticationPolicySiloMutationResult
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	mods, err := authenticationSiloChanges(request.Properties, request.Changes)
	if err != nil {
		return result, err
	}
	if len(mods) == 0 && request.ProtectedFromAccidentalDeletion == nil {
		return result, ErrInvalidAuthenticationSilo
	}
	if len(mods) != 0 && request.ProtectedFromAccidentalDeletion != nil && request.Options.ExpectedVersion != nil {
		return result, ErrObjectControlUnsupported
	}
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	options, _, err := c.authenticationSiloOptions(ctx, request.Options)
	if err != nil {
		return result, err
	}
	result.Mutation, err = c.objectMutationIdentity(ctx, request.Identity, options, ResolveIdentityOptions{Properties: options.Properties}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		if err := authenticationSiloScope(root, *observed.Object); err != nil {
			return err
		}
		if err := authenticationPolicyWritePrerequisites(ctx, session, root, nil); err != nil {
			return err
		}
		if err := authenticationProtectionAvailable(session, root, request.ProtectedFromAccidentalDeletion, request.Options.Properties); err != nil {
			return err
		}
		if err := resolveSiloPolicies(ctx, session, c.config, root, request.Properties, mods, &result); err != nil {
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
			if err := verifyAuthenticationSiloWrite(mutation, mods, ""); err != nil {
				return err
			}
		}
		return authenticationPolicyProtection(ctx, session, root, c.config, mutation, options, request.ProtectedFromAccidentalDeletion, request.Options.Properties, &result.Protection)
	})
	return finishAuthenticationSiloMutation(result, err)
}

func (c *Client) DeleteAuthenticationPolicySilo(ctx context.Context, request DeleteAuthenticationPolicySiloRequest) (ObjectMutationResult, error) {
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return ObjectMutationResult{}, err
	}
	if c == nil || c.session == nil {
		return ObjectMutationResult{}, ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	options, _, err := c.authenticationSiloOptions(ctx, request.Options)
	if err != nil {
		return ObjectMutationResult{}, err
	}
	return c.objectMutation(ctx, request.Identity, options, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		if err := authenticationSiloScope(root, *observed.Object); err != nil {
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

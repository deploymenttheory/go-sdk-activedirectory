package model

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

func InternalSiloPolicyIdentities(properties AuthenticationPolicySiloProperties) []struct {
	InternalAttribute string
	InternalIdentity  *Identity
} {
	return []struct {
		InternalAttribute string
		InternalIdentity  *Identity
	}{
		{"msDS-UserAuthNPolicy", properties.UserAuthenticationPolicy},
		{"msDS-ComputerAuthNPolicy", properties.ComputerAuthenticationPolicy},
		{"msDS-ServiceAuthNPolicy", properties.ServiceAuthenticationPolicy},
	}
}

func InternalSiloPolicyAttribute(name string) bool {
	switch strings.ToLower(name) {
	case "msds-userauthnpolicy", "msds-computerauthnpolicy", "msds-serviceauthnpolicy":
		return true
	}
	return false
}

func InternalAuthenticationSiloChanges(
	properties AuthenticationPolicySiloProperties,
	raw []AttributeChange,
) ([]InternalLdapAttributeModification, error) {
	changes := slices.Clone(raw)
	for _, change := range raw {
		switch strings.ToLower(change.Attribute) {
		case "ntsecuritydescriptor",
			"msds-authnpolicysilomembers",
			"msds-assignedauthnpolicysilobl",
			"msds-assignedauthnpolicy",
			"msds-assignedauthnpolicysilo":
			return nil, ErrInvalidAuthenticationSilo
		}
	}
	if properties.Description != nil {
		if !InternalValidDirectoryText(*properties.Description) {
			return nil, ErrInvalidAuthenticationSilo
		}
		changes = append(
			changes,
			InternalAuthenticationSetting("description", *properties.Description),
		)
	}
	if properties.Enforced != nil {
		value := "FALSE"
		if *properties.Enforced {
			value = "TRUE"
		}
		changes = append(
			changes,
			InternalAuthenticationSetting("msDS-AuthNPolicySiloEnforced", value),
		)
	}
	for _, reference := range InternalSiloPolicyIdentities(properties) {
		if reference.InternalIdentity == nil {
			continue
		}
		if err := InternalValidateIdentityOperation(
			*reference.InternalIdentity,
			ResolveIdentityOptions{},
		); err != nil {
			return nil, err
		}
		// The placeholder is replaced by a resolved canonical DN before dispatch.
		changes = append(
			changes,
			InternalAuthenticationSetting(reference.InternalAttribute, "pending"),
		)
	}
	if len(changes) == 0 {
		return nil, nil
	}
	mods, err := InternalObjectChanges(changes)
	if err != nil {
		return nil, err
	}
	for _, mod := range mods {
		if mod.InternalOperation == 1 && len(mod.InternalValues) == 0 {
			continue
		}
		if strings.EqualFold(mod.InternalAttribute, "msDS-AuthNPolicySiloEnforced") {
			if len(mod.InternalValues) != 1 {
				return nil, ErrInvalidAuthenticationSilo
			}
			if _, err := InternalParseLDAPBool(string(mod.InternalValues[0])); err != nil {
				return nil, ErrInvalidAuthenticationSilo
			}
		}
		if InternalSiloPolicyAttribute(mod.InternalAttribute) && len(mod.InternalValues) != 1 {
			return nil, ErrInvalidAuthenticationSilo
		}
	}
	return mods, nil
}

func InternalResolveSiloPolicies(
	ctx context.Context,
	session InternalDirectorySession,
	config Config,
	root RootDSE,
	properties AuthenticationPolicySiloProperties,
	mods []InternalLdapAttributeModification,
	result *AuthenticationPolicySiloMutationResult,
) error {
	for i := range mods {
		mod := &mods[i]
		if !InternalSiloPolicyAttribute(mod.InternalAttribute) || len(mod.InternalValues) == 0 {
			continue
		}
		var identity *Identity
		for _, reference := range InternalSiloPolicyIdentities(properties) {
			if strings.EqualFold(reference.InternalAttribute, mod.InternalAttribute) {
				identity = reference.InternalIdentity
			}
		}
		if identity == nil {
			parsed, err := IdentityByDN(string(mod.InternalValues[0]))
			if err != nil {
				return err
			}
			identity = &parsed
		}
		observed, err := InternalResolveIdentitySession(
			ctx,
			session,
			config,
			root,
			*identity,
			ResolveIdentityOptions{
				Partition:  *root.ConfigurationNamingContext,
				Properties: InternalAuthenticationPolicyProperties(nil),
			},
		)
		result.PolicyObservations = append(result.PolicyObservations, observed)
		if err != nil {
			return err
		}
		if err := InternalAuthenticationPolicyScope(root, *observed.Object); err != nil {
			return err
		}
		mod.InternalValues = [][]byte{[]byte(observed.Object.DistinguishedName)}
	}
	return nil
}

func InternalFinishAuthenticationSiloMutation(
	result AuthenticationPolicySiloMutationResult,
	err error,
) (AuthenticationPolicySiloMutationResult, error) {
	object := result.Mutation.After
	if object == nil && result.Mutation.State == ObjectWriteNotAttempted &&
		result.Protection.ProtectedFromAccidentalDeletion != nil {
		object = result.Mutation.Before
	}
	if object != nil {
		silo, decodeErr := InternalDecodeAuthenticationSilo(*object)
		silo.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.Silo = &silo
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

func InternalVerifyAuthenticationSiloWrite(
	ctx context.Context,
	session InternalDirectorySession,
	root RootDSE,
	mutation *ObjectMutationResult,
	mods []InternalLdapAttributeModification,
	name string,
) error {
	return InternalVerifyObjectWriteWithSchema(ctx, session, root, mutation, mods, name)
}

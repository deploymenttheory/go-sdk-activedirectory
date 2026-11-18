package authentication_policies

import (
	"context"
	"errors"
	"slices"
	"strings"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// AuthenticationPolicy resolves an explicit DN/GUID inside this forest's policy
// container. Missing values remain nil, not inferred defaults. Protection is
// read only when requested in Properties, using the existing ACL observation.
//
// Related cmdlet: Get-ADAuthenticationPolicy.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adauthenticationpolicy?view=windowsserver2025-ps
func (c *Service) AuthenticationPolicy(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ResolveIdentityOptions,
) (AuthenticationPolicyResult, error) {
	var result admodel.AuthenticationPolicyResult
	if options.Target != admodel.IdentityTargetObject {
		return result, admodel.ErrUnsupportedIdentity
	}
	if err := admodel.InternalValidateIdentityOperation(identity, options); err != nil {
		return result, err
	}
	protection := slices.ContainsFunc(
		options.Properties,
		func(name string) bool { return strings.EqualFold(name, "ProtectedFromAccidentalDeletion") },
	)
	options.Properties = admodel.InternalAuthenticationPolicyProperties(options.Properties)
	err := adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		if _, err := admodel.InternalAuthenticationPolicyContainer(root); err != nil {
			return err
		}
		if options.Partition != "" &&
			!admodel.InternalSameAuthenticationDN(
				options.Partition,
				*root.ConfigurationNamingContext,
			) {
			return admodel.ErrIdentityScope
		}
		options.Partition = *root.ConfigurationNamingContext
		result.Observation, err = admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			identity,
			options,
		)
		if err != nil {
			return err
		}
		if err := admodel.InternalAuthenticationPolicyScope(
			root,
			*result.Observation.Object,
		); err != nil {
			return err
		}
		policy, err := admodel.InternalDecodeAuthenticationPolicy(*result.Observation.Object)
		result.Policy = &policy
		if err != nil || !protection {
			return err
		}
		result.Protection, err = admodel.InternalReadOUProtection(
			ctx,
			adengine.InternalClientSession(c.engine()),
			root,
			adengine.InternalClientConfig(c.engine()),
			admodel.OrganizationalUnit{
				DistinguishedName: policy.DistinguishedName,
				GUID:              policy.GUID,
			},
			options.Partition,
		)
		result.Policy.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		return err
	})
	return result, err
}

// AuthenticationPolicies intersects the caller's shared typed/LDAP filter with
// msDS-AuthNPolicy and defaults to a one-level search of the policy container.
// A Name equality filter supplies explicit name lookup without guessing a DN.
//
// Related cmdlet: Get-ADAuthenticationPolicy.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adauthenticationpolicy?view=windowsserver2025-ps
func (c *Service) AuthenticationPolicies(
	ctx context.Context,
	options adshared.SearchOptions,
) (AuthenticationPoliciesResult, error) {
	var result admodel.AuthenticationPoliciesResult
	if err := options.Validate(); err != nil {
		return result, err
	}
	protection := slices.ContainsFunc(
		options.Properties,
		func(name string) bool { return strings.EqualFold(name, "ProtectedFromAccidentalDeletion") },
	)
	options.Properties = admodel.InternalAuthenticationPolicyProperties(options.Properties)
	if !admodel.InternalFilterUnset(options.TypedFilter) {
		options.TypedFilter = admodel.FilterAnd(
			admodel.FilterEqual("objectClass", admodel.FilterText("msDS-AuthNPolicy")),
			options.TypedFilter,
		)
	} else if options.Filter == "" {
		options.Filter = "(objectClass=msDS-AuthNPolicy)"
	} else {
		options.Filter = "(&(objectClass=msDS-AuthNPolicy)" + options.Filter + ")"
	}
	err := adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		container, err := admodel.InternalAuthenticationPolicyContainer(root)
		if err != nil {
			return err
		}
		if options.Base == "" {
			options.Base, options.Scope = container, admodel.ScopeOneLevel
		}
		base, err := admodel.InternalParseIdentityDN(options.Base)
		if err != nil {
			return err
		}
		parent, _ := admodel.InternalParseIdentityDN(container)
		if !admodel.InternalIdentityWithin(base, parent) {
			return admodel.ErrIdentityScope
		}
		result.Observation, err = admodel.InternalSearchIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			options,
		)
		searchErr := err
		for _, raw := range result.Observation.Objects {
			policy, decodeErr := admodel.InternalDecodeAuthenticationPolicy(raw)
			decodeErr = errors.Join(decodeErr, admodel.InternalAuthenticationPolicyScope(root, raw))
			if protection && decodeErr == nil && searchErr == nil {
				observed, readErr := admodel.InternalReadOUProtection(
					ctx,
					adengine.InternalClientSession(c.engine()),
					root,
					adengine.InternalClientConfig(c.engine()),
					admodel.OrganizationalUnit{
						DistinguishedName: policy.DistinguishedName,
						GUID:              policy.GUID,
					},
					*root.ConfigurationNamingContext,
				)
				policy.ProtectedFromAccidentalDeletion = observed.ProtectedFromAccidentalDeletion
				result.Protection = append(result.Protection, observed)
				decodeErr = errors.Join(decodeErr, readErr)
			}
			result.Policies = append(result.Policies, policy)
			err = errors.Join(err, decodeErr)
		}
		if err != nil {
			result.Observation.Complete = false
		}
		return err
	})
	return result, err
}

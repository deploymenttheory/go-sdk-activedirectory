package authentication_silos

import (
	"context"
	"errors"
	"slices"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

func (c *Service) AuthenticationPolicySilo(
	ctx context.Context,
	identity adshared.Identity,
	options AuthenticationPolicySiloReadOptions,
) (AuthenticationPolicySiloResult, error) {
	var result admodel.AuthenticationPolicySiloResult
	if options.Target != admodel.IdentityTargetObject {
		return result, admodel.ErrUnsupportedIdentity
	}
	protection := admodel.InternalAuthenticationProtectionRequested(options.Properties)
	options.Properties = admodel.InternalAuthenticationSiloProperties(options.Properties)
	if err := admodel.InternalValidateIdentityOperation(
		identity,
		options.ResolveIdentityOptions,
	); err != nil {
		return result, err
	}
	limit, err := admodel.InternalAuthenticationSiloLimit(options.MaxMembers)
	if err != nil {
		return result, err
	}
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		if _, err := admodel.InternalAuthenticationSiloContainer(root); err != nil {
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
			options.ResolveIdentityOptions,
		)
		if err != nil {
			return err
		}
		properties := options.Properties
		if protection {
			properties = append(slices.Clone(properties), "ProtectedFromAccidentalDeletion")
		}
		return admodel.InternalReadAuthenticationSilo(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			*result.Observation.Object,
			limit,
			properties,
			&result,
		)
	})
	return result, err
}

func (c *Service) AuthenticationPolicySilos(
	ctx context.Context,
	options AuthenticationPolicySiloSearchOptions,
) (AuthenticationPolicySilosResult, error) {
	var result admodel.AuthenticationPolicySilosResult
	protection := admodel.InternalAuthenticationProtectionRequested(options.Properties)
	options.Properties = admodel.InternalAuthenticationSiloProperties(options.Properties)
	if err := options.SearchOptions.Validate(); err != nil {
		return result, err
	}
	limit, err := admodel.InternalAuthenticationSiloLimit(options.MaxMembers)
	if err != nil {
		return result, err
	}
	if !admodel.InternalFilterUnset(options.TypedFilter) {
		options.TypedFilter = admodel.FilterAnd(
			admodel.FilterEqual("objectClass", admodel.FilterText("msDS-AuthNPolicySilo")),
			options.TypedFilter,
		)
	} else if options.Filter == "" {
		options.Filter = "(objectClass=msDS-AuthNPolicySilo)"
	} else {
		options.Filter = "(&(objectClass=msDS-AuthNPolicySilo)" + options.Filter + ")"
	}
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		container, err := admodel.InternalAuthenticationSiloContainer(root)
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
			options.SearchOptions,
		)
		searchErr := err
		properties := options.Properties
		if protection {
			properties = append(slices.Clone(properties), "ProtectedFromAccidentalDeletion")
		}
		for _, object := range result.Observation.Objects {
			row := admodel.AuthenticationPolicySiloResult{
				Observation: admodel.IdentityResult{
					Object:     &object,
					Candidates: []admodel.Object{object},
					Complete:   searchErr == nil,
				},
			}
			if searchErr == nil {
				err = errors.Join(
					err,
					admodel.InternalReadAuthenticationSilo(
						ctx,
						adengine.InternalClientSession(c.engine()),
						adengine.InternalClientConfig(c.engine()),
						root,
						object,
						limit,
						properties,
						&row,
					),
				)
			} else {
				silo, decodeErr := admodel.InternalDecodeAuthenticationSilo(object)
				row.Silo = &silo
				err = errors.Join(err, decodeErr)
			}
			result.Silos = append(result.Silos, row)
		}
		if err != nil {
			result.Observation.Complete = false
		}
		return err
	})
	return result, err
}

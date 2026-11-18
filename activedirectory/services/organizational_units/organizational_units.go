package organizational_units

import (
	"context"
	"errors"
	"slices"
	"strings"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// OrganizationalUnit resolves an explicit DN/GUID using the common identity
// rules and verifies its class. Missing typed attributes remain nil.
//
// Related cmdlet: Get-ADOrganizationalUnit.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adorganizationalunit?view=windowsserver2025-ps
func (c *Service) OrganizationalUnit(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ResolveIdentityOptions,
) (OrganizationalUnitResult, error) {
	if options.Target != admodel.IdentityTargetObject {
		return admodel.OrganizationalUnitResult{}, admodel.ErrUnsupportedIdentity
	}
	wantProtection := slices.ContainsFunc(
		options.Properties,
		func(name string) bool { return strings.EqualFold(name, "ProtectedFromAccidentalDeletion") },
	)
	options.Properties = admodel.InternalOrganizationalUnitProperties(options.Properties)
	var result admodel.OrganizationalUnitResult
	if err := admodel.InternalValidateIdentityOperation(identity, options); err != nil {
		return result, err
	}
	err := adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		observed, err := admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			identity,
			options,
		)
		result.Observation = observed
		if err != nil {
			return err
		}
		unit, err := admodel.InternalDecodeOrganizationalUnit(*observed.Object)
		result.Unit = &unit
		if err != nil || !wantProtection {
			return err
		}
		result.Protection, err = admodel.InternalReadOUProtection(
			ctx,
			adengine.InternalClientSession(c.engine()),
			root,
			adengine.InternalClientConfig(c.engine()),
			unit,
			observed.Partition,
		)
		result.Unit.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		return err
	})
	return result, err
}

// OrganizationalUnits uses the SDK's existing LDAP SearchOptions, including
// explicit scope, paging and caller limits. An empty Base selects the configured
// partition or the endpoint's default NC. The filter is intersected with the OU
// class filter; no PowerShell-expression parsing or fallback scope is performed.
//
// Related cmdlet: Get-ADOrganizationalUnit.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adorganizationalunit?view=windowsserver2025-ps
func (c *Service) OrganizationalUnits(
	ctx context.Context,
	options adshared.SearchOptions,
) (OrganizationalUnitsResult, error) {
	var result admodel.OrganizationalUnitsResult
	if err := options.Validate(); err != nil {
		return result, err
	}
	wantProtection := slices.ContainsFunc(
		options.Properties,
		func(name string) bool { return strings.EqualFold(name, "ProtectedFromAccidentalDeletion") },
	)
	options.Properties = admodel.InternalOrganizationalUnitProperties(options.Properties)
	switch {
	case !admodel.InternalFilterUnset(options.TypedFilter):
		options.TypedFilter = admodel.FilterAnd(
			admodel.FilterEqual("objectClass", admodel.FilterText("organizationalUnit")),
			options.TypedFilter,
		)
	case options.Filter == "":
		options.Filter = "(objectClass=organizationalUnit)"
	default:
		options.Filter = "(&(objectClass=organizationalUnit)" + options.Filter + ")"
	}
	err := adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		if err := root.Capabilities().RequireAD("OrganizationalUnits"); err != nil {
			return err
		}
		if options.Base == "" {
			options.Base = adengine.InternalClientConfig(c.engine()).Partition
			if options.Base == "" && root.DefaultNamingContext != nil {
				options.Base = *root.DefaultNamingContext
			}
			if options.Base == "" {
				return admodel.ErrNoDefaultPartition
			}
		}
		identity, err := admodel.IdentityByDN(options.Base)
		if err != nil {
			return err
		}
		selected, contexts, err := admodel.InternalIdentityPartition(
			identity,
			adengine.InternalClientConfig(c.engine()).Partition,
			root,
		)
		if err != nil {
			return err
		}
		result.Observation, err = admodel.InternalSearchIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			options,
		)
		searchErr := err
		for _, object := range result.Observation.Objects {
			unit, decodeErr := admodel.InternalDecodeOrganizationalUnit(object)
			dn, scopeErr := admodel.InternalParseIdentityDN(object.DistinguishedName)
			if scopeErr != nil || admodel.InternalIdentityNamingContext(dn, contexts) != selected {
				decodeErr = errors.Join(decodeErr, admodel.ErrIdentityScope)
			}
			if wantProtection {
				var protection admodel.OUProtectionResult
				if decodeErr == nil && searchErr == nil {
					protection, decodeErr = admodel.InternalReadOUProtection(
						ctx,
						adengine.InternalClientSession(c.engine()),
						root,
						adengine.InternalClientConfig(c.engine()),
						unit,
						root.NamingContexts[selected],
					)
					unit.ProtectedFromAccidentalDeletion = protection.ProtectedFromAccidentalDeletion
				}
				result.Protection = append(result.Protection, protection)
			}
			result.Units = append(result.Units, unit)
			err = errors.Join(err, decodeErr)
		}
		if err != nil {
			result.Observation.Complete = false
		}
		return err
	})
	return result, err
}

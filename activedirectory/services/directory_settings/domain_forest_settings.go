package directory_settings

import (
	"context"
	"strings"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// UpdateDomain submits one LDAP Modify, retaining server diagnostics and the
// shared accepted/rejected/uncertain result. It does not contact another DC.
//
// Related cmdlet: Set-ADDomain.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-addomain?view=windowsserver2025-ps
func (c *Service) UpdateDomain(
	ctx context.Context,
	request UpdateDomainRequest,
) (adshared.ObjectMutationResult, error) {
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	changes, err := admodel.InternalDomainSettingsChanges(request)
	if err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	return internalServiceUpdateDirectorySettings(
		c,
		ctx,
		request.Identity,
		request.Options,
		changes,
		false,
	)
}

// UpdateForest changes suffix settings on this forest's Partitions container.
// It does not change trust routing, DNS records, account names, or SPNs on users.
//
// Related cmdlet: Set-ADForest.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adforest?view=windowsserver2025-ps
func (c *Service) UpdateForest(
	ctx context.Context,
	request UpdateForestRequest,
) (adshared.ObjectMutationResult, error) {
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	changes := append([]admodel.AttributeChange(nil), request.Changes...)
	for _, value := range []struct {
		InternalName   string
		InternalValues *[]string
	}{{"uPNSuffixes", request.UPNSuffixes}, {"msDS-SPNSuffixes", request.SPNSuffixes}} {
		if value.InternalValues != nil {
			change, err := admodel.InternalDirectorySuffixChange(
				value.InternalName,
				*value.InternalValues,
			)
			if err != nil {
				return admodel.ObjectMutationResult{}, err
			}
			changes = append(changes, change)
		}
	}
	return internalServiceUpdateDirectorySettings(
		c,
		ctx,
		request.Identity,
		request.Options,
		changes,
		true,
	)
}

// internalServiceUpdateDirectorySettings resolves the domain or forest settings object and submits its
// validated attribute changes.
func internalServiceUpdateDirectorySettings(c *Service,
	ctx context.Context,
	identity admodel.Identity,
	options admodel.ObjectMutationOptions,
	changes []admodel.AttributeChange,
	forest bool,
) (admodel.ObjectMutationResult, error) {
	mods, err := admodel.InternalDirectorySettingsModifications(changes, forest)
	if err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	return adengine.InternalClientObjectMutation(
		c.engine(),
		ctx,
		identity,
		options,
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, resolved admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			if err := admodel.InternalDirectorySettingsTarget(
				ctx,
				session,
				root,
				*resolved.Object,
				forest,
			); err != nil {
				return err
			}
			for _, mod := range mods {
				if strings.EqualFold(
					mod.InternalAttribute,
					"msDS-ExpirePasswordsOnSmartCardOnlyAccounts",
				) &&
					mod.InternalOperation != 1 &&
					len(mod.InternalValues) == 1 &&
					strings.EqualFold(string(mod.InternalValues[0]), "TRUE") &&
					(root.DomainFunctionality == nil || *root.DomainFunctionality < uint32(admodel.FunctionalLevelWindows2016)) {
					return admodel.InternalFunctionalLevelPrerequisite(
						"smart-card-only account password rolling requires Windows Server 2016",
					)
				}
			}
			controls, err := admodel.InternalObjectWriteControls(
				root,
				adengine.InternalClientConfig(c.engine()).Endpoint,
				options,
				*result.TargetGUID,
				false,
			)
			if err != nil {
				return err
			}
			if err := admodel.InternalSubmitObjectWrite(
				ctx,
				session,
				admodel.InternalLdapWriteRequest{
					InternalOperation:     admodel.InternalLdapWriteModify,
					InternalDn:            admodel.InternalObjectGUIDTarget(*result.TargetGUID),
					InternalModifications: mods,
					InternalControls:      controls,
				},
				false,
				result,
			); err != nil {
				return err
			}
			if err := admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				admodel.InternalObjectGUIDIdentity(*result.TargetGUID),
				result,
				admodel.InternalObjectWriteProperties(options, mods),
				false,
			); err != nil {
				return err
			}
			return admodel.InternalVerifyObjectWriteWithSchema(ctx, session, root, result, mods, "")
		},
	)
}

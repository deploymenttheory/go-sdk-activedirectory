package password_policies

import (
	"context"
	"strings"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// CreateFineGrainedPasswordPolicy requires all settings explicitly; it does not
// silently import a PowerShell/default-domain template. One Add creates the PSO
// under the connected domain's Password Settings Container.
func (c *Service) CreateFineGrainedPasswordPolicy(
	ctx context.Context,
	request CreateFineGrainedPasswordPolicyRequest,
) (FineGrainedPasswordPolicyMutationResult, error) {
	var result admodel.FineGrainedPasswordPolicyMutationResult
	changes, err := admodel.InternalFineGrainedSettingsChanges(request.Settings, true)
	if err != nil {
		return result, err
	}
	if err := admodel.InternalFineGrainedSettingsRelationships(
		admodel.FineGrainedPasswordPolicySettings{},
		request.Settings,
		true,
	); err != nil {
		return result, err
	}
	text, err := admodel.InternalFineGrainedTextChanges(request.Description, request.DisplayName)
	if err != nil {
		return result, err
	}
	changes = append(changes, text...)
	if request.Name == "" || !admodel.InternalValidDirectoryText(request.Name) {
		return result, admodel.ErrInvalidFineGrainedPolicy
	}
	if request.Options.ExpectedVersion != nil {
		return result, admodel.ErrObjectControlUnsupported
	}
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	// Discovery and generic creation share one budget; neither stage can restart
	// Config.Timeout after the previous stage has consumed part of it.
	ctx, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()
	root, err := c.engine().RootDSE(ctx, admodel.RootDSEOptions{})
	if err != nil {
		return result, err
	}
	domain, err := admodel.InternalFineGrainedPolicyDomain(
		root,
		adengine.InternalClientConfig(c.engine()),
		request.Options.Partition,
	)
	if err != nil {
		return result, err
	}
	parent, err := admodel.IdentityByDN(admodel.InternalFineGrainedPolicyContainer(domain))
	if err != nil {
		return result, err
	}
	attributes := make(map[string][]admodel.RawValue, len(changes))
	for _, change := range changes {
		attributes[change.Attribute] = change.Values
	}
	request.Options.Partition = domain
	request.Options.Properties = admodel.InternalFineGrainedPolicyProperties(
		request.Options.Properties,
	)
	return admodel.InternalFineGrainedMutationResult(
		c.engine().
			CreateObject(ctx, admodel.CreateObjectRequest{Parent: parent, Class: "msDS-PasswordSettings", Name: request.Name, Attributes: attributes, Options: request.Options}),
	)
}

func internalServiceMutateFineGrainedPolicy(c *Service,
	ctx context.Context,
	identity admodel.Identity,
	options admodel.ObjectMutationOptions,
	workflow admodel.InternalObjectMutationWorkflow,
) (admodel.ObjectMutationResult, error) {
	resolve := admodel.ResolveIdentityOptions{
		Partition:  options.Partition,
		Properties: admodel.InternalFineGrainedPolicyProperties(options.Properties),
	}
	return adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		identity,
		options,
		resolve,
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			domain, err := admodel.InternalFineGrainedPolicyDomain(
				root,
				adengine.InternalClientConfig(c.engine()),
				options.Partition,
			)
			if err != nil {
				return err
			}
			if err := admodel.InternalFineGrainedPolicyLocation(
				*observed.Object,
				domain,
			); err != nil {
				return err
			}
			return workflow(ctx, session, root, observed, result)
		},
	)
}

// UpdateFineGrainedPasswordPolicy submits all selected changes atomically in
// one strict Modify. The server validates resulting cross-field constraints.
func (c *Service) UpdateFineGrainedPasswordPolicy(
	ctx context.Context,
	request UpdateFineGrainedPasswordPolicyRequest,
) (FineGrainedPasswordPolicyMutationResult, error) {
	if err := admodel.InternalFineGrainedMutationOptions(
		request.Identity,
		request.Options,
	); err != nil {
		return admodel.FineGrainedPasswordPolicyMutationResult{}, err
	}
	changes, err := admodel.InternalFineGrainedSettingsChanges(request.Settings, false)
	if err != nil {
		return admodel.FineGrainedPasswordPolicyMutationResult{}, err
	}
	text, err := admodel.InternalFineGrainedTextChanges(request.Description, request.DisplayName)
	if err != nil {
		return admodel.FineGrainedPasswordPolicyMutationResult{}, err
	}
	changes = append(changes, text...)
	for _, change := range request.Changes {
		for _, managed := range admodel.InternalFineGrainedPolicyProperties(nil) {
			if strings.EqualFold(change.Attribute, managed) &&
				!strings.EqualFold(managed, "description") &&
				!strings.EqualFold(managed, "displayName") {
				return admodel.FineGrainedPasswordPolicyMutationResult{}, admodel.ErrInvalidFineGrainedPolicy
			}
		}
		changes = append(changes, change)
	}
	mods, err := admodel.InternalObjectChanges(changes)
	if err != nil {
		return admodel.FineGrainedPasswordPolicyMutationResult{}, err
	}
	mutation, err := internalServiceMutateFineGrainedPolicy(
		c,
		ctx,
		request.Identity,
		request.Options,
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			before, err := admodel.InternalDecodeFineGrainedPolicy(*observed.Object)
			if err != nil {
				return err
			}
			if err := admodel.InternalFineGrainedSettingsRelationships(
				before.Settings,
				request.Settings,
				false,
			); err != nil {
				return err
			}
			controls, err := admodel.InternalObjectWriteControls(
				root,
				adengine.InternalClientConfig(c.engine()).Endpoint,
				request.Options,
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
			options := request.Options
			options.Properties = admodel.InternalFineGrainedPolicyProperties(options.Properties)
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
			return admodel.InternalVerifyObjectWrite(result, mods, "")
		},
	)
	return admodel.InternalFineGrainedMutationResult(mutation, err)
}

// DeleteFineGrainedPasswordPolicy is a leaf delete. It never removes subjects
// themselves, disables protection or retries a rejected/uncertain request.
func (c *Service) DeleteFineGrainedPasswordPolicy(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ObjectMutationOptions,
) (adshared.ObjectMutationResult, error) {
	if err := admodel.InternalFineGrainedMutationOptions(identity, options); err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	return internalServiceMutateFineGrainedPolicy(
		c,
		ctx,
		identity,
		options,
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, _ admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
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
					InternalOperation: admodel.InternalLdapWriteDelete,
					InternalDn:        admodel.InternalObjectGUIDTarget(*result.TargetGUID),
					InternalControls:  controls,
				},
				false,
				result,
			); err != nil {
				return err
			}
			return admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				admodel.InternalObjectGUIDIdentity(*result.TargetGUID),
				result,
				[]string{"objectGUID"},
				true,
			)
		},
	)
}

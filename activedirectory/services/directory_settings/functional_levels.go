package directory_settings

import (
	"context"
	"errors"
	"strconv"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// SetDomainMode submits a single functional-level change on the connected PDC.
// It supports raises and explicit supported lowering, with no automatic replay.
func (c *Service) SetDomainMode(
	ctx context.Context,
	request FunctionalLevelTransitionRequest,
) (FunctionalLevelTransitionResult, error) {
	return internalServiceSetFunctionalLevel(c, ctx, request, false)
}

// SetForestMode targets the Schema Master, as specified by MS-ADTS 3.1.1.5.3.4
// and the current Set-ADForestMode cmdlet. It never follows a role referral.
func (c *Service) SetForestMode(
	ctx context.Context,
	request FunctionalLevelTransitionRequest,
) (FunctionalLevelTransitionResult, error) {
	return internalServiceSetFunctionalLevel(c, ctx, request, true)
}

func internalServiceSetFunctionalLevel(c *Service,
	ctx context.Context,
	request admodel.FunctionalLevelTransitionRequest,
	forest bool,
) (admodel.FunctionalLevelTransitionResult, error) {
	result := admodel.FunctionalLevelTransitionResult{
		Requested: request.Level,
		Role:      admodel.OperationMasterPDCEmulator,
	}
	if forest {
		result.Role = admodel.OperationMasterSchemaMaster
	}
	if !admodel.InternalKnownFunctionalLevel(request.Level) {
		return result, admodel.ErrInvalidFunctionalLevel
	}
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	mutation, err := adengine.InternalClientObjectMutation(
		c.engine(),
		ctx,
		request.Identity,
		request.Options,
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, resolved admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			if err := admodel.InternalDirectorySettingsTarget(
				ctx,
				session,
				root,
				*resolved.Object,
				forest,
			); err != nil {
				return err
			}
			target, plans, err := admodel.InternalPrepareOperationMasters(
				ctx,
				session,
				[]admodel.OperationMasterRole{result.Role},
			)
			if err != nil {
				return err
			}
			result.RoleOwnerDN = plans[0].InternalOwner
			if !admodel.InternalSameSettingsDN(target, result.RoleOwnerDN) {
				return admodel.ErrFunctionalLevelRoleOwner
			}
			controls, err := admodel.InternalObjectWriteControls(
				root,
				adengine.InternalClientConfig(c.engine()).Endpoint,
				request.Options,
				*mutation.TargetGUID,
				false,
			)
			if err != nil {
				return err
			}
			properties := append(
				[]string{
					"objectGUID",
					"objectClass",
					"msDS-Behavior-Version",
					"nTMixedDomain",
					"msDS-ExpirePasswordsOnSmartCardOnlyAccounts",
				},
				request.Options.Properties...)
			before, err := admodel.InternalFunctionalLevelRead(
				ctx,
				session,
				mutation.TargetDN,
				properties,
				&result,
			)
			if err != nil {
				return err
			}
			value, err := before.Values("objectGUID").Single()
			if err != nil {
				return err
			}
			guid, err := value.GUID()
			if err != nil || guid != *mutation.TargetGUID {
				return errors.Join(admodel.ErrInvalidResult, err)
			}
			mutation.Before = &before
			current, err := admodel.InternalObservedFunctionalLevel(before)
			if err != nil {
				return err
			}
			result.Current = &current
			advertised := root.DomainFunctionality
			if forest {
				advertised = root.ForestFunctionality
			}
			if advertised == nil || admodel.FunctionalLevel(*advertised) != current {
				return admodel.InternalFunctionalLevelPrerequisite(
					"RootDSE and the authoritative level attribute disagree or are unavailable",
				)
			}
			if current == request.Level {
				if request.Options.ExpectedVersion != nil {
					return admodel.ErrObjectControlUnsupported
				}
				mutation.After, mutation.ReadbackComplete, mutation.Verified = &before, true, true
				result.Unchanged = true
				return nil
			}
			if request.Level < current && !request.AllowLowering {
				return admodel.ErrFunctionalLevelLowering
			}
			if err := admodel.InternalFunctionalLevelPrerequisites(
				ctx,
				session,
				root,
				before,
				request.Level,
				forest,
				&result,
			); err != nil {
				return err
			}
			result.PreflightComplete = true
			mods := []admodel.InternalLdapAttributeModification{
				{
					InternalOperation: 2,
					InternalAttribute: "msDS-Behavior-Version",
					InternalValues: [][]byte{
						[]byte(strconv.FormatUint(uint64(request.Level), 10)),
					},
				},
			}
			if err := admodel.InternalSubmitObjectWrite(
				ctx,
				session,
				admodel.InternalLdapWriteRequest{
					InternalOperation:     admodel.InternalLdapWriteModify,
					InternalDn:            admodel.InternalObjectGUIDTarget(guid),
					InternalModifications: mods,
					InternalControls:      controls,
				},
				false,
				mutation,
			); err != nil {
				return err
			}
			if err := admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				admodel.InternalObjectGUIDIdentity(guid),
				mutation,
				admodel.InternalObjectWriteProperties(request.Options, mods),
				false,
			); err != nil {
				return err
			}
			return admodel.InternalVerifyObjectWrite(mutation, mods, "")
		},
	)
	result.Mutation = mutation
	return result, err
}

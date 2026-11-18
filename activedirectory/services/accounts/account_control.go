package accounts

import (
	"context"
	"errors"
	"slices"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// AccountControl reads persisted options and the selected server's computed
// state under one client timeout. It does not infer lockout from old timestamps.
//
// Related cmdlet: Get-ADUser.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2025-ps
func (c *Service) AccountControl(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ResolveIdentityOptions,
) (AccountControlResult, error) {
	var result admodel.AccountControlResult
	if options.Target > admodel.IdentityTargetAccount {
		return result, admodel.ErrInvalidIdentity
	}
	options = admodel.InternalAccountControlIdentity(
		identity,
		options.Partition,
		options.Properties,
	)
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
		result.Observation, err = admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			identity,
			options,
		)
		if result.Observation.Object != nil {
			account, decodeErr := admodel.InternalDecodeAccountControl(
				*result.Observation.Object,
				root.Capabilities().Type,
			)
			result.Account = &account
			err = errors.Join(err, decodeErr)
		}
		return err
	})
	return result, err
}

// UpdateAccountControl applies one atomic Modify using exact-old value removal
// for stored flags. It does not write computed lockout/password-expiry bits.
//
// Related cmdlet: Set-ADAccountControl.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountcontrol?view=windowsserver2025-ps
func (c *Service) UpdateAccountControl(
	ctx context.Context,
	request AccountControlRequest,
) (AccountControlMutationResult, error) {
	if admodel.InternalAccountControlPatchEmpty(request.Patch) {
		return admodel.AccountControlMutationResult{}, admodel.ErrInvalidAccountControl
	}
	if err := admodel.InternalValidateAccountControlPatch(request.Patch); err != nil {
		return admodel.AccountControlMutationResult{}, err
	}
	return internalServiceMutateAccountControl(c,
		ctx,
		request.Identity,
		request.Options,
		request.Patch,
		false,
	)
}

// EnableAccount enables the selected account by updating its stored account-control flag. Options
// select the partition, write controls, and readback properties.
//
// Related cmdlet: Enable-ADAccount.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/enable-adaccount?view=windowsserver2025-ps
func (c *Service) EnableAccount(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ObjectMutationOptions,
) (AccountControlMutationResult, error) {
	enabled := true
	return c.UpdateAccountControl(
		ctx,
		admodel.AccountControlRequest{
			Identity: identity,
			Options:  options,
			Patch:    admodel.AccountControlPatch{Enabled: &enabled},
		},
	)
}

// DisableAccount disables the selected account by updating its stored account-control flag. Options
// select the partition, write controls, and readback properties.
//
// Related cmdlet: Disable-ADAccount.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/disable-adaccount?view=windowsserver2025-ps
func (c *Service) DisableAccount(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ObjectMutationOptions,
) (AccountControlMutationResult, error) {
	enabled := false
	return c.UpdateAccountControl(
		ctx,
		admodel.AccountControlRequest{
			Identity: identity,
			Options:  options,
			Patch:    admodel.AccountControlPatch{Enabled: &enabled},
		},
	)
}

// UnlockAccount writes lockoutTime=0 on the selected server. It does not alter
// disabled status, manufacture a computed flag, or prove forest-wide convergence.
//
// Related cmdlet: Unlock-ADAccount.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/unlock-adaccount?view=windowsserver2025-ps
func (c *Service) UnlockAccount(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ObjectMutationOptions,
) (AccountControlMutationResult, error) {
	return internalServiceMutateAccountControl(c,
		ctx,
		identity,
		options,
		admodel.AccountControlPatch{},
		true,
	)
}

// internalServiceMutateAccountControl resolves an account, applies flag or unlock changes, and records
// the write and readback outcomes.
func internalServiceMutateAccountControl(c *Service,
	ctx context.Context,
	identity admodel.Identity,
	options admodel.ObjectMutationOptions,
	patch admodel.AccountControlPatch,
	unlock bool,
) (admodel.AccountControlMutationResult, error) {
	resolve := admodel.InternalAccountControlIdentity(
		identity,
		options.Partition,
		options.Properties,
	)
	if err := admodel.InternalValidateIdentityOperation(identity, resolve); err != nil {
		return admodel.AccountControlMutationResult{}, err
	}
	for _, property := range options.Properties {
		if property == "1.1" {
			return admodel.AccountControlMutationResult{}, admodel.ErrInvalidProperty
		}
	}
	options.Properties = admodel.InternalAccountControlProperties(options.Properties)
	var kind admodel.DirectoryType
	mutation, err := adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		identity,
		options,
		resolve,
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			kind = root.Capabilities().Type
			if err := admodel.InternalAccountControlClass(*observed.Object, kind); err != nil {
				return err
			}
			writes, verification, err := admodel.InternalAccountControlChanges(
				*observed.Object,
				kind,
				patch,
			)
			if err != nil {
				return err
			}
			if unlock {
				writes = []admodel.InternalLdapAttributeModification{
					admodel.InternalAccountValueVerification("lockoutTime", []byte("0")),
				}
				verification = slices.Clone(writes)
			}
			if len(writes) == 0 {
				if options.ExpectedVersion != nil {
					return admodel.ErrObjectControlUnsupported
				}
				result.After, result.ReadbackComplete = observed.Object, observed.Complete
				return admodel.InternalVerifyObjectWrite(result, verification, "")
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
					InternalModifications: writes,
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
				admodel.InternalObjectWriteProperties(options, writes),
				false,
			); err != nil {
				return err
			}
			if patch.ChangePasswordAtLogon != nil && !*patch.ChangePasswordAtLogon {
				// -1 is a write instruction, never the readback value. A positive
				// server timestamp confirms the requested state, not exact timing.
				value, err := result.After.Values("pwdLastSet").Single()
				if err != nil {
					return errors.Join(admodel.ErrObjectVerification, err)
				}
				ticks, err := value.Int64()
				if err != nil || ticks <= 0 {
					return errors.Join(admodel.ErrObjectVerification, err)
				}
			}
			return admodel.InternalVerifyObjectWrite(result, verification, "")
		},
	)
	result := admodel.AccountControlMutationResult{Mutation: mutation}
	if mutation.After != nil {
		state, decodeErr := admodel.InternalDecodeAccountControl(*mutation.After, kind)
		result.Account = &state
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

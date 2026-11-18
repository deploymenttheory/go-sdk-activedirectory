package computers

import (
	"context"
	"errors"
	"slices"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// Computer resolves one computer account and returns its typed projection and identity observation.
// Options select the partition and additional properties; a projection may accompany a decoding error.
//
// Related cmdlet: Get-ADComputer.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer?view=windowsserver2025-ps
func (c *Service) Computer(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ResolveIdentityOptions,
) (ComputerResult, error) {
	var result admodel.ComputerResult
	if options.Target > admodel.IdentityTargetAccount {
		return result, admodel.ErrInvalidIdentity
	}
	options = admodel.InternalComputerIdentityOptions(
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
			computer, decodeErr := admodel.InternalDecodeComputer(
				*result.Observation.Object,
				root.Capabilities().Type,
			)
			result.Computer = &computer
			err = errors.Join(err, decodeErr)
		}
		return err
	})
	return result, err
}

// Computers searches computer accounts using the caller's typed or raw LDAP filter, paging, and result
// bounds. The computer class restriction is added to the filter; partial observations and decoding
// errors are retained.
//
// Related cmdlet: Get-ADComputer.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer?view=windowsserver2025-ps
func (c *Service) Computers(
	ctx context.Context,
	options adshared.SearchOptions,
) (ComputersResult, error) {
	var result admodel.ComputersResult
	if err := options.Validate(); err != nil {
		return result, err
	}
	options.Properties = admodel.InternalComputerProperties(options.Properties)
	class := admodel.InternalComputerClassFilter()
	if !admodel.InternalFilterUnset(options.TypedFilter) {
		options.TypedFilter = admodel.FilterAnd(class, options.TypedFilter)
	} else if options.Filter != "" {
		encoded, _ := class.LDAP()
		options.Filter = "(&" + encoded + options.Filter + ")"
	} else {
		options.TypedFilter = class
	}
	err := adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		if root.Capabilities().Type == admodel.DirectoryUnknown {
			return root.Capabilities().RequireADDS("Computers")
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
		if _, _, err := admodel.InternalIdentityPartition(
			identity,
			adengine.InternalClientConfig(c.engine()).Partition,
			root,
		); err != nil {
			return err
		}
		result.Observation, err = admodel.InternalSearchIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			options,
		)
		for _, object := range result.Observation.Objects {
			computer, decodeErr := admodel.InternalDecodeComputer(object, root.Capabilities().Type)
			result.Computers = append(result.Computers, computer)
			err = errors.Join(err, decodeErr)
		}
		return err
	})
	return result, err
}

// UpdateComputer changes a computer account's typed properties, raw attributes, and stored account
// flags. Request selects the account and write controls; the result retains write acceptance and
// readback state on error.
//
// Related cmdlet: Set-ADComputer.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adcomputer?view=windowsserver2025-ps
func (c *Service) UpdateComputer(
	ctx context.Context,
	request UpdateComputerRequest,
) (ComputerMutationResult, error) {
	if err := admodel.InternalValidateIdentityOperation(
		request.Identity,
		admodel.InternalComputerIdentityOptions(
			request.Identity,
			request.Options.Partition,
			request.Options.Properties,
		),
	); err != nil {
		return admodel.ComputerMutationResult{}, err
	}
	if err := admodel.InternalValidateAccountControlPatch(request.Control); err != nil {
		return admodel.ComputerMutationResult{}, err
	}
	changes, err := admodel.InternalComputerAttributeChanges(request.Properties, request.Changes)
	if err != nil {
		return admodel.ComputerMutationResult{}, err
	}
	var mods []admodel.InternalLdapAttributeModification
	if len(changes) > 0 {
		mods, err = admodel.InternalObjectChanges(changes)
		if err != nil {
			return admodel.ComputerMutationResult{}, err
		}
	} else if admodel.InternalAccountControlPatchEmpty(request.Control) && !admodel.InternalComputerHasEncryption(request.Properties) {
		return admodel.ComputerMutationResult{}, admodel.ErrInvalidComputer
	}
	request.Options.Properties = admodel.InternalComputerProperties(request.Options.Properties)
	mutation, err := adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		request.Identity,
		request.Options,
		admodel.InternalComputerIdentityOptions(
			request.Identity,
			request.Options.Partition,
			request.Options.Properties,
		),
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			if err := root.Capabilities().RequireADDS("UpdateComputer"); err != nil {
				return err
			}
			if err := admodel.InternalComputerClass(*observed.Object); err != nil {
				return err
			}
			writes, verification := slices.Clone(mods), slices.Clone(mods)
			if !admodel.InternalAccountControlPatchEmpty(request.Control) {
				more, verify, err := admodel.InternalAccountControlChanges(
					*observed.Object,
					admodel.DirectoryADDS,
					request.Control,
				)
				if err != nil {
					return err
				}
				writes = append(writes, more...)
				verification = append(verification, verify...)
			}
			more, verify, err := admodel.InternalComputerEncryptionChanges(
				*observed.Object,
				request.Properties,
			)
			if err != nil {
				return err
			}
			writes = append(writes, more...)
			verification = append(verification, verify...)
			if len(writes) == 0 {
				if request.Options.ExpectedVersion != nil {
					return admodel.ErrObjectControlUnsupported
				}
				result.After, result.ReadbackComplete = observed.Object, observed.Complete
				return admodel.InternalVerifyObjectWrite(result, verification, "")
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
				admodel.InternalObjectWriteProperties(request.Options, writes),
				false,
			); err != nil {
				return err
			}
			if request.Control.ChangePasswordAtLogon != nil &&
				!*request.Control.ChangePasswordAtLogon {
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
	return admodel.InternalComputerMutationResult(mutation, err)
}

// DeleteComputer deletes the selected computer account as a leaf object. It does not perform recursive
// deletion; the mutation result retains the accepted or uncertain write outcome.
//
// Related cmdlet: Remove-ADComputer.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adcomputer?view=windowsserver2025-ps
func (c *Service) DeleteComputer(
	ctx context.Context,
	request DeleteComputerRequest,
) (ComputerMutationResult, error) {
	if err := admodel.InternalValidateIdentityOperation(
		request.Identity,
		admodel.InternalComputerIdentityOptions(
			request.Identity,
			request.Options.Partition,
			request.Options.Properties,
		),
	); err != nil {
		return admodel.ComputerMutationResult{}, err
	}
	mutation, err := adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		request.Identity,
		request.Options,
		admodel.InternalComputerIdentityOptions(request.Identity, request.Options.Partition, nil),
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			if err := root.Capabilities().RequireADDS("DeleteComputer"); err != nil {
				return err
			}
			if err := admodel.InternalComputerClass(*observed.Object); err != nil {
				return err
			}
			controls, err := admodel.InternalObjectWriteControls(
				root,
				adengine.InternalClientConfig(c.engine()).Endpoint,
				request.Options,
				*result.TargetGUID,
				request.Recursive,
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
				request.Recursive,
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
	return admodel.InternalComputerMutationResult(mutation, err)
}

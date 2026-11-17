package service_accounts

import (
	"context"
	"errors"
	"slices"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

func (c *Service) ServiceAccount(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ResolveIdentityOptions,
) (result ServiceAccountResult, err error) {
	if options.Target > admodel.IdentityTargetAccount {
		return result, admodel.ErrInvalidIdentity
	}
	if err = admodel.InternalValidateServiceAccountProjection(options.Properties); err != nil {
		return
	}
	options = admodel.InternalServiceAccountIdentityOptions(
		identity,
		options.Partition,
		options.Properties,
	)
	if err = admodel.InternalValidateIdentityOperation(identity, options); err != nil {
		return
	}
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, e := admodel.InternalReadIdentityRoot(ctx, adengine.InternalClientSession(c.engine()))
		if e != nil {
			return e
		}
		if e = root.Capabilities().RequireADDS("ServiceAccount"); e != nil {
			return e
		}
		result.Observation, e = admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			identity,
			options,
		)
		if result.Observation.Object != nil {
			account, x := admodel.InternalDecodeServiceAccount(*result.Observation.Object)
			result.Account = &account
			e = errors.Join(e, x)
		}
		return e
	})
	return
}

func (c *Service) ServiceAccounts(
	ctx context.Context,
	options adshared.SearchOptions,
) (result ServiceAccountsResult, err error) {
	if err = options.Validate(); err != nil {
		return
	}
	if err = admodel.InternalValidateServiceAccountProjection(options.Properties); err != nil {
		return
	}
	options.Properties = admodel.InternalServiceAccountProperties(options.Properties)
	class := admodel.InternalServiceAccountClassFilter()
	if !admodel.InternalFilterUnset(options.TypedFilter) {
		options.TypedFilter = admodel.FilterAnd(class, options.TypedFilter)
	} else if options.Filter != "" {
		encoded, _ := class.LDAP()
		options.Filter = "(&" + encoded + options.Filter + ")"
	} else {
		options.TypedFilter = class
	}
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, e := admodel.InternalReadIdentityRoot(ctx, adengine.InternalClientSession(c.engine()))
		if e != nil {
			return e
		}
		if e = root.Capabilities().RequireADDS("ServiceAccounts"); e != nil {
			return e
		}
		if options.Base == "" {
			if root.DefaultNamingContext == nil {
				return admodel.ErrNoDefaultPartition
			}
			options.Base = *root.DefaultNamingContext
		}
		id, e := admodel.IdentityByDN(options.Base)
		if e != nil {
			return e
		}
		if _, _, e = admodel.InternalIdentityPartition(
			id,
			adengine.InternalClientConfig(c.engine()).Partition,
			root,
		); e != nil {
			return e
		}
		result.Observation, e = admodel.InternalSearchIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			options,
		)
		for _, object := range result.Observation.Objects {
			account, x := admodel.InternalDecodeServiceAccount(object)
			result.Accounts = append(result.Accounts, account)
			e = errors.Join(e, x)
		}
		return e
	})
	return
}

func (c *Service) UpdateServiceAccount(
	ctx context.Context,
	request UpdateServiceAccountRequest,
) (ServiceAccountMutationResult, error) {
	if err := admodel.InternalValidateServiceAccountProjection(
		request.Options.Properties,
	); err != nil {
		return admodel.ServiceAccountMutationResult{}, err
	}
	if err := admodel.InternalValidateServiceAccountControl(request.Control); err != nil {
		return admodel.ServiceAccountMutationResult{}, err
	}
	changes, err := admodel.InternalServiceAccountChanges(request.Properties, request.Changes)
	if err != nil {
		return admodel.ServiceAccountMutationResult{}, err
	}
	var mods []admodel.InternalLdapAttributeModification
	if len(changes) > 0 {
		mods, err = admodel.InternalObjectChanges(changes)
		if err != nil {
			return admodel.ServiceAccountMutationResult{}, err
		}
	} else if admodel.InternalAccountControlPatchEmpty(request.Control) &&
		!admodel.InternalComputerHasEncryption(admodel.InternalServiceAccountComputerProperties(request.Properties)) &&
		request.PasswordReaders == nil {
		return admodel.ServiceAccountMutationResult{}, admodel.ErrInvalidServiceAccount
	}
	request.Options.Properties = admodel.InternalServiceAccountProperties(
		request.Options.Properties,
	)
	m, err := adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		request.Identity,
		request.Options,
		admodel.InternalServiceAccountIdentityOptions(
			request.Identity,
			request.Options.Partition,
			request.Options.Properties,
		),
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			if err := root.Capabilities().RequireADDS("UpdateServiceAccount"); err != nil {
				return err
			}
			if root.Capabilities().Has("1.2.840.113556.1.4.1920") {
				return admodel.ErrObjectWriteTarget
			}
			kind, err := admodel.InternalServiceAccountClass(*observed.Object)
			if err != nil {
				return err
			}
			writes, verify := slices.Clone(mods), slices.Clone(mods)
			more, verification, err := admodel.InternalAccountControlChanges(
				*observed.Object,
				admodel.DirectoryADDS,
				request.Control,
			)
			if err != nil {
				return err
			}
			writes = append(writes, more...)
			verify = append(verify, verification...)
			more, verification, err = admodel.InternalComputerEncryptionChanges(
				*observed.Object,
				admodel.InternalServiceAccountComputerProperties(request.Properties),
			)
			if err != nil {
				return err
			}
			writes = append(writes, more...)
			verify = append(verify, verification...)
			if request.PasswordReaders != nil {
				if kind != admodel.ServiceAccountGroupManaged {
					return admodel.ErrInvalidServiceAccount
				}
				value, err := observed.Object.Values("msDS-GroupMSAMembership").Single()
				if err != nil {
					return err
				}
				sids, err := admodel.InternalResolveServiceAccountReaders(
					ctx,
					session,
					adengine.InternalClientConfig(c.engine()),
					root,
					*request.PasswordReaders,
					result.Partition,
				)
				if err != nil {
					return err
				}
				next, err := admodel.InternalReplaceServiceAccountReaders(
					session,
					value.Bytes(),
					sids,
				)
				if err != nil {
					return err
				}
				writes = append(
					writes,
					admodel.InternalAccountConditionalValue(
						"msDS-GroupMSAMembership",
						value.Bytes(),
						next,
					)...)
				verify = append(
					verify,
					admodel.InternalAccountValueVerification("msDS-GroupMSAMembership", next),
				)
			}
			if len(writes) == 0 {
				if request.Options.ExpectedVersion != nil {
					return admodel.ErrObjectControlUnsupported
				}
				result.After, result.ReadbackComplete = observed.Object, observed.Complete
				return admodel.InternalVerifyObjectWrite(result, verify, "")
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
			if err = admodel.InternalSubmitObjectWrite(
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
			if err = admodel.InternalObserveObjectWrite(
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
			return admodel.InternalVerifyObjectWrite(result, verify, "")
		},
	)
	return admodel.InternalServiceAccountMutationResult(m, err)
}

func (c *Service) DeleteServiceAccount(
	ctx context.Context,
	request DeleteServiceAccountRequest,
) (ServiceAccountMutationResult, error) {
	if err := admodel.InternalValidateServiceAccountProjection(
		request.Options.Properties,
	); err != nil {
		return admodel.ServiceAccountMutationResult{}, err
	}
	m, err := adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		request.Identity,
		request.Options,
		admodel.InternalServiceAccountIdentityOptions(
			request.Identity,
			request.Options.Partition,
			nil,
		),
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			if err := root.Capabilities().RequireADDS("DeleteServiceAccount"); err != nil {
				return err
			}
			if root.Capabilities().Has("1.2.840.113556.1.4.1920") {
				return admodel.ErrObjectWriteTarget
			}
			if _, err := admodel.InternalServiceAccountClass(*observed.Object); err != nil {
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
			if err = admodel.InternalSubmitObjectWrite(
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
	return admodel.InternalServiceAccountMutationResult(m, err)
}

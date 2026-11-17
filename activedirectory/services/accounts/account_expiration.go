package accounts

import (
	"context"
	"errors"
	"math"
	"slices"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

func (c *Service) AccountExpiration(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ResolveIdentityOptions,
) (result AccountExpirationResult, err error) {
	if options.Target > admodel.IdentityTargetAccount {
		return result, admodel.ErrInvalidIdentity
	}
	options = admodel.InternalAccountControlIdentity(
		identity,
		options.Partition,
		append(slices.Clone(options.Properties), "accountExpires"),
	)
	if err := admodel.InternalValidateIdentityOperation(identity, options); err != nil {
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
		if root.Capabilities().Type == admodel.DirectoryADDS &&
			(adengine.InternalClientConfig(c.engine()).Endpoint.Port == 3268 || adengine.InternalClientConfig(c.engine()).Endpoint.Port == 3269) {
			return admodel.ErrAccountStateTarget
		}
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
		if err := admodel.InternalAccountControlClass(
			*result.Observation.Object,
			root.Capabilities().Type,
		); err != nil {
			return err
		}
		expiration, err := admodel.InternalDecodeAccountExpiration(*result.Observation.Object)
		result.Expiration = &expiration
		return err
	})
	return result, err
}

func (c *Service) SetAccountExpiration(
	ctx context.Context,
	request SetAccountExpirationRequest,
) (AccountExpirationMutationResult, error) {
	stamp, err := admodel.InternalFiniteAccountTime(request.At)
	if err != nil {
		return admodel.AccountExpirationMutationResult{}, err
	}
	return internalServiceWriteAccountExpiration(c, ctx, request.Identity, request.Options, stamp)
}

// ClearAccountExpiration writes MaxInt64, matching the ActiveDirectory module's
// AccountExpirationDate clear conversion. Both 0 and MaxInt64 are recognized on
// reads. Clearing does not delete the attribute or write the -1 instruction.
func (c *Service) ClearAccountExpiration(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ObjectMutationOptions,
) (AccountExpirationMutationResult, error) {
	return internalServiceWriteAccountExpiration(c, ctx, identity, options, math.MaxInt64)
}

func internalServiceWriteAccountExpiration(c *Service,
	ctx context.Context,
	identity admodel.Identity,
	options admodel.ObjectMutationOptions,
	stamp admodel.FileTime,
) (admodel.AccountExpirationMutationResult, error) {
	resolve := admodel.InternalAccountControlIdentity(
		identity,
		options.Partition,
		append(slices.Clone(options.Properties), "accountExpires"),
	)
	if err := admodel.InternalValidateIdentityOperation(identity, resolve); err != nil {
		return admodel.AccountExpirationMutationResult{}, err
	}
	mod := admodel.InternalLdapAttributeModification{
		InternalOperation: 2,
		InternalAttribute: "accountExpires",
		InternalValues:    [][]byte{[]byte(stamp.LDAPString())},
	}
	mutation, err := adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		identity,
		options,
		resolve,
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			if err := admodel.InternalAccountControlClass(
				*observed.Object,
				root.Capabilities().Type,
			); err != nil {
				return err
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
					InternalModifications: []admodel.InternalLdapAttributeModification{mod},
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
				admodel.InternalAccountControlProperties(
					admodel.InternalObjectWriteProperties(
						options,
						[]admodel.InternalLdapAttributeModification{mod},
					),
				),
				false,
			); err != nil {
				return err
			}
			return admodel.InternalVerifyObjectWrite(
				result,
				[]admodel.InternalLdapAttributeModification{mod},
				"",
			)
		},
	)
	result := admodel.AccountExpirationMutationResult{Mutation: mutation}
	if mutation.After != nil {
		expiration, decodeErr := admodel.InternalDecodeAccountExpiration(*mutation.After)
		result.Expiration = &expiration
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

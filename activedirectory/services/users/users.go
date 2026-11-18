package users

import (
	"context"
	"errors"
	"slices"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// User resolves one user or inetOrgPerson object and returns its typed projection and identity
// observation. Computer subclasses are excluded; options select the partition and additional
// properties.
//
// Related cmdlet: Get-ADUser.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2025-ps
func (c *Service) User(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ResolveIdentityOptions,
) (UserResult, error) {
	if options.Target > admodel.IdentityTargetAccount {
		return admodel.UserResult{}, admodel.ErrInvalidIdentity
	}
	options = admodel.InternalUserIdentityOptions(identity, options.Partition, options.Properties)
	observed, err := c.engine().ResolveIdentity(ctx, identity, options)
	result := admodel.UserResult{Observation: observed}
	if observed.Object != nil {
		user, decodeErr := admodel.InternalDecodeUser(*observed.Object)
		result.User = &user
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

// Users searches user/inetOrgPerson objects while excluding computer subclasses.
// Typed and raw filters retain SearchOptions' mutual exclusion and bounds.
//
// Related cmdlet: Get-ADUser.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2025-ps
func (c *Service) Users(ctx context.Context, options adshared.SearchOptions) (UsersResult, error) {
	var result admodel.UsersResult
	if err := options.Validate(); err != nil {
		return result, err
	}
	options.Properties = admodel.InternalUserProperties(options.Properties)
	class := admodel.FilterAnd(
		admodel.FilterOr(
			admodel.FilterEqual("objectClass", admodel.FilterText("user")),
			admodel.FilterEqual("objectClass", admodel.FilterText("inetOrgPerson")),
		),
		admodel.FilterNot(admodel.FilterEqual("objectClass", admodel.FilterText("computer"))),
	)
	switch {
	case !admodel.InternalFilterUnset(options.TypedFilter):
		options.TypedFilter = admodel.FilterAnd(class, options.TypedFilter)
	case options.Filter != "":
		encoded, _ := class.LDAP()
		options.Filter = "(&" + encoded + options.Filter + ")"
	default:
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
		if err := root.Capabilities().RequireAD("Users"); err != nil {
			return errors.Join(admodel.ErrUserCapability, err)
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
			user, decodeErr := admodel.InternalDecodeUser(object)
			result.Users = append(result.Users, user)
			err = errors.Join(err, decodeErr)
		}
		return err
	})
	return result, err
}

// UpdateUser changes the selected user's typed properties, raw attributes, and stored account flags.
// The result retains write acceptance and readback state when a later step fails.
//
// Related cmdlet: Set-ADUser.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-aduser?view=windowsserver2025-ps
func (c *Service) UpdateUser(
	ctx context.Context,
	request UpdateUserRequest,
) (UserMutationResult, error) {
	if err := admodel.InternalValidateUserMutation(request.Identity, request.Options); err != nil {
		return admodel.UserMutationResult{}, err
	}
	changes, err := admodel.InternalUserAttributeChanges(request.Properties, request.Changes)
	if err != nil {
		return admodel.UserMutationResult{}, err
	}
	var mods []admodel.InternalLdapAttributeModification
	if len(changes) > 0 {
		mods, err = admodel.InternalObjectChanges(changes)
		if err != nil {
			return admodel.UserMutationResult{}, err
		}
	} else if !admodel.InternalUserHasFlags(request.Properties) {
		return admodel.UserMutationResult{}, admodel.ErrInvalidUser
	}
	request.Options.Properties = admodel.InternalUserProperties(request.Options.Properties)
	mutation, err := adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		request.Identity,
		request.Options,
		admodel.InternalUserIdentityOptions(
			request.Identity,
			request.Options.Partition,
			request.Options.Properties,
		),
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			if err := admodel.InternalUserClass(*observed.Object); err != nil {
				return err
			}
			writes, verification := slices.Clone(mods), slices.Clone(mods)
			flagWrites, flagVerification, err := admodel.InternalUserFlagChanges(
				*observed.Object,
				root.Capabilities().Type,
				request.Properties,
			)
			if err != nil {
				return err
			}
			writes = append(writes, flagWrites...)
			verification = append(verification, flagVerification...)
			if len(writes) == 0 {
				if request.Options.ExpectedVersion != nil {
					return admodel.ErrObjectControlUnsupported
				}
				result.After, result.ReadbackComplete = observed.Object, observed.Complete
				return admodel.InternalVerifyObjectWriteWithSchema(ctx, session, root, result, verification, "")
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
			return admodel.InternalVerifyObjectWriteWithSchema(ctx, session, root, result, verification, "")
		},
	)
	return admodel.InternalUserMutationResult(mutation, err)
}

// DeleteUser is leaf-only and never deletes group objects or their members.
//
// Related cmdlet: Remove-ADUser.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-aduser?view=windowsserver2025-ps
func (c *Service) DeleteUser(
	ctx context.Context,
	request DeleteUserRequest,
) (UserMutationResult, error) {
	if err := admodel.InternalValidateUserMutation(request.Identity, request.Options); err != nil {
		return admodel.UserMutationResult{}, err
	}
	mutation, err := adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		request.Identity,
		request.Options,
		admodel.InternalUserIdentityOptions(request.Identity, request.Options.Partition, nil),
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			if err := admodel.InternalUserClass(*observed.Object); err != nil {
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
	return admodel.InternalUserMutationResult(mutation, err)
}

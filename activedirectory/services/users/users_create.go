package users

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_accounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/accounts"
)

// CreateUser creates disabled, optionally resets the initial password, then
// enables only when explicitly requested. Enablement without password setup
// additionally requires explicit PasswordNotRequired=true. Stages are not a
// transaction; any accepted/uncertain stage stops on error and is never replayed.
//
// Related cmdlet: New-ADUser.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-aduser?view=windowsserver2025-ps
func (c *Service) CreateUser(
	ctx context.Context,
	request CreateUserRequest,
) (result UserCreationResult, err error) {
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	request, wantEnabled, err := prepareUserCreation(request)
	if err != nil {
		return result, err
	}
	bounded, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()
	var kind admodel.DirectoryType
	err = adengine.InternalClientRead(c.engine(), bounded, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		kind = root.Capabilities().Type
		if err := root.Capabilities().RequireAD("CreateUser"); err != nil {
			return errors.Join(admodel.ErrUserCapability, err)
		}
		if request.InitialPassword != nil {
			session, ok := adengine.InternalClientSession(c.engine()).(admodel.InternalPasswordSession)
			if !ok {
				return errors.Join(admodel.ErrPasswordProtection, admodel.ErrUnsupported)
			}
			protection, err := session.InternalPasswordProtection(
				ctx,
				adengine.InternalClientConfig(c.engine()).Transport,
			)
			if err != nil {
				return errors.Join(admodel.ErrPasswordProtection, err)
			}
			if protection.Transport != adengine.InternalClientConfig(c.engine()).Transport ||
				protection.CipherBits < 128 {
				return admodel.ErrPasswordProtection
			}
		}
		request.Parent, err = admodel.InternalAccountCreationParent(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			request.Parent,
			request.Options,
			admodel.InternalWellKnownUsers,
		)
		return err
	})
	if err != nil {
		return result, err
	}
	attributes, err := admodel.InternalUserCreationAttributes(request, kind)
	if err != nil {
		return result, err
	}
	request.Options.Properties = admodel.InternalUserProperties(request.Options.Properties)
	result.Creation, err = c.engine().
		CreateObject(bounded, admodel.CreateObjectRequest{Parent: request.Parent, Class: request.Class, Name: request.Name, Attributes: attributes, Options: request.Options})
	if result.Creation.After != nil {
		user, decodeErr := admodel.InternalDecodeUser(*result.Creation.After)
		result.User = &user
		err = errors.Join(err, decodeErr)
	}
	if err != nil {
		return result, admodel.InternalCreationIncomplete(
			admodel.ErrUserCreationIncomplete,
			result.Creation,
			err,
		)
	}
	if result.Creation.TargetGUID == nil || !result.Creation.Verified {
		return result, errors.Join(admodel.ErrUserCreationIncomplete, admodel.ErrObjectVerification)
	}
	account := admodel.InternalObjectGUIDIdentity(*result.Creation.TargetGUID)
	partition := result.Creation.Partition
	if request.InitialPassword != nil {
		password, passwordErr := adservice_accounts.New(c.engine()).
			ResetAccountPassword(bounded, admodel.PasswordResetRequest{Identity: account, Partition: partition, NewPassword: request.InitialPassword})
		result.Password = &password
		if passwordErr != nil || password.State != admodel.ObjectWriteAccepted {
			return result, errors.Join(admodel.ErrUserCreationIncomplete, passwordErr)
		}
	}
	if wantEnabled {
		enabled := true
		update, updateErr := c.UpdateUser(
			bounded,
			admodel.UpdateUserRequest{
				Identity:   account,
				Properties: admodel.UserProperties{Enabled: &enabled},
				Options: admodel.ObjectMutationOptions{
					Partition:  partition,
					Properties: request.Options.Properties,
				},
			},
		)
		result.Enable = &update.Mutation
		if update.User != nil {
			result.User = update.User
		}
		if updateErr != nil || !update.Mutation.Verified {
			return result, errors.Join(admodel.ErrUserCreationIncomplete, updateErr)
		}
	} else if request.InitialPassword != nil {
		// Password setup can change server-maintained timestamps. Retain the
		// creation observation separately instead of presenting it as current.
		observation, readErr := c.User(
			bounded,
			account,
			admodel.ResolveIdentityOptions{
				Partition:  partition,
				Properties: request.Options.Properties,
			},
		)
		result.Observation = &observation
		if observation.User != nil {
			result.User = observation.User
		}
		if readErr != nil {
			return result, errors.Join(admodel.ErrUserCreationIncomplete, readErr)
		}
	}
	result.Complete = true
	return result, nil
}

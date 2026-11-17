package computers

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_accounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/accounts"
)

// CreateComputer creates disabled, optionally resets an explicit password, then
// enables only if requested. Enabling without password setup additionally needs
// explicit PasswordNotRequired=true. No random password or domain join occurs.
func (c *Service) CreateComputer(
	ctx context.Context,
	request CreateComputerRequest,
) (result ComputerCreationResult, err error) {
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	if err := admodel.InternalValidateAccountCreationOptions(
		request.Parent,
		request.Options,
	); err != nil {
		return result, err
	}
	if request.Options.ExpectedVersion != nil {
		return result, admodel.ErrObjectControlUnsupported
	}
	if request.Name == "" || !admodel.InternalValidDirectoryText(request.Name) {
		return result, admodel.ErrInvalidComputer
	}
	wantEnabled := request.Control.Enabled != nil && *request.Control.Enabled
	withoutPassword := request.Control.PasswordNotRequired != nil &&
		*request.Control.PasswordNotRequired
	if wantEnabled && request.InitialPassword == nil && !withoutPassword {
		return result, admodel.ErrInvalidComputer
	}
	if request.InitialPassword != nil {
		if err := admodel.InternalValidatePasswordBytes(request.InitialPassword); err != nil {
			return result, err
		}
	}
	attributes, err := admodel.InternalComputerCreationAttributes(request)
	if err != nil {
		return result, err
	}
	bounded, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()
	err = adengine.InternalClientRead(c.engine(), bounded, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		if err := root.Capabilities().RequireADDS("CreateComputer"); err != nil {
			return err
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
			admodel.InternalWellKnownComputers,
		)
		return err
	})
	if err != nil {
		return result, err
	}
	request.Options.Properties = admodel.InternalComputerProperties(request.Options.Properties)
	result.Creation, err = c.engine().
		CreateObject(bounded, admodel.CreateObjectRequest{Parent: request.Parent, Class: "computer", Name: request.Name, Attributes: attributes, Options: request.Options})
	if result.Creation.After != nil {
		computer, decodeErr := admodel.InternalDecodeComputer(
			*result.Creation.After,
			admodel.DirectoryADDS,
		)
		result.Computer = &computer
		err = errors.Join(err, decodeErr)
	}
	if err != nil {
		return result, admodel.InternalCreationIncomplete(
			admodel.ErrComputerCreationIncomplete,
			result.Creation,
			err,
		)
	}
	if result.Creation.TargetGUID == nil || !result.Creation.Verified {
		return result, errors.Join(
			admodel.ErrComputerCreationIncomplete,
			admodel.ErrObjectVerification,
		)
	}
	account := admodel.InternalObjectGUIDIdentity(*result.Creation.TargetGUID)
	partition := result.Creation.Partition
	if request.InitialPassword != nil {
		password, passwordErr := adservice_accounts.New(c.engine()).
			ResetAccountPassword(bounded, admodel.PasswordResetRequest{Identity: account, Partition: partition, NewPassword: request.InitialPassword})
		result.Password = &password
		if passwordErr != nil || password.State != admodel.ObjectWriteAccepted {
			return result, errors.Join(admodel.ErrComputerCreationIncomplete, passwordErr)
		}
	}
	if wantEnabled {
		enabled := true
		update, updateErr := c.UpdateComputer(
			bounded,
			admodel.UpdateComputerRequest{
				Identity: account,
				Control:  admodel.AccountControlPatch{Enabled: &enabled},
				Options: admodel.ObjectMutationOptions{
					Partition:  partition,
					Properties: request.Options.Properties,
				},
			},
		)
		result.Enable = &update.Mutation
		if update.Computer != nil {
			result.Computer = update.Computer
		}
		if updateErr != nil || !update.Mutation.Verified {
			return result, errors.Join(admodel.ErrComputerCreationIncomplete, updateErr)
		}
	} else if request.InitialPassword != nil {
		observation, readErr := c.Computer(
			bounded,
			account,
			admodel.ResolveIdentityOptions{
				Partition:  partition,
				Properties: request.Options.Properties,
			},
		)
		result.Observation = &observation
		if observation.Computer != nil {
			result.Computer = observation.Computer
		}
		if readErr != nil {
			return result, errors.Join(admodel.ErrComputerCreationIncomplete, readErr)
		}
	}
	result.Complete = true
	return result, nil
}

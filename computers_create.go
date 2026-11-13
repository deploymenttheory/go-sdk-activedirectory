package activedirectory

import (
	"context"
	"errors"
)

// CreateComputer creates disabled, optionally resets an explicit password, then
// enables only if requested. Enabling without password setup additionally needs
// explicit PasswordNotRequired=true. No random password or domain join occurs.
func (c *Client) CreateComputer(ctx context.Context, request CreateComputerRequest) (result ComputerCreationResult, err error) {
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	if err := validateAccountCreationOptions(request.Parent, request.Options); err != nil {
		return result, err
	}
	if request.Options.ExpectedVersion != nil {
		return result, ErrObjectControlUnsupported
	}
	if request.Name == "" || !validDirectoryText(request.Name) {
		return result, ErrInvalidComputer
	}
	wantEnabled := request.Control.Enabled != nil && *request.Control.Enabled
	withoutPassword := request.Control.PasswordNotRequired != nil && *request.Control.PasswordNotRequired
	if wantEnabled && request.InitialPassword == nil && !withoutPassword {
		return result, ErrInvalidComputer
	}
	if request.InitialPassword != nil {
		if err := validatePasswordBytes(request.InitialPassword); err != nil {
			return result, err
		}
	}
	attributes, err := computerCreationAttributes(request)
	if err != nil {
		return result, err
	}
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	err = c.read(bounded, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		if err := root.Capabilities().RequireADDS("CreateComputer"); err != nil {
			return err
		}
		if request.InitialPassword != nil {
			session, ok := c.session.(passwordSession)
			if !ok {
				return errors.Join(ErrPasswordProtection, ErrUnsupported)
			}
			protection, err := session.passwordProtection(ctx, c.config.Transport)
			if err != nil {
				return errors.Join(ErrPasswordProtection, err)
			}
			if protection.Transport != c.config.Transport || protection.CipherBits < 128 {
				return ErrPasswordProtection
			}
		}
		request.Parent, err = accountCreationParent(ctx, c.session, c.config, root, request.Parent, request.Options, wellKnownComputers)
		return err
	})
	if err != nil {
		return result, err
	}
	request.Options.Properties = computerProperties(request.Options.Properties)
	result.Creation, err = c.CreateObject(bounded, CreateObjectRequest{Parent: request.Parent, Class: "computer", Name: request.Name, Attributes: attributes, Options: request.Options})
	if result.Creation.After != nil {
		computer, decodeErr := decodeComputer(*result.Creation.After, DirectoryADDS)
		result.Computer = &computer
		err = errors.Join(err, decodeErr)
	}
	if err != nil {
		return result, errors.Join(ErrComputerCreationIncomplete, err)
	}
	if result.Creation.TargetGUID == nil || !result.Creation.Verified {
		return result, errors.Join(ErrComputerCreationIncomplete, ErrObjectVerification)
	}
	account := objectGUIDIdentity(*result.Creation.TargetGUID)
	partition := result.Creation.Partition
	if request.InitialPassword != nil {
		password, passwordErr := c.ResetAccountPassword(bounded, PasswordResetRequest{Identity: account, Partition: partition, NewPassword: request.InitialPassword})
		result.Password = &password
		if passwordErr != nil || password.State != ObjectWriteAccepted {
			return result, errors.Join(ErrComputerCreationIncomplete, passwordErr)
		}
	}
	if wantEnabled {
		enabled := true
		update, updateErr := c.UpdateComputer(bounded, UpdateComputerRequest{Identity: account, Control: AccountControlPatch{Enabled: &enabled}, Options: ObjectMutationOptions{Partition: partition, Properties: request.Options.Properties}})
		result.Enable = &update.Mutation
		if update.Computer != nil {
			result.Computer = update.Computer
		}
		if updateErr != nil || !update.Mutation.Verified {
			return result, errors.Join(ErrComputerCreationIncomplete, updateErr)
		}
	} else if request.InitialPassword != nil {
		observation, readErr := c.Computer(bounded, account, ResolveIdentityOptions{Partition: partition, Properties: request.Options.Properties})
		result.Observation = &observation
		if observation.Computer != nil {
			result.Computer = observation.Computer
		}
		if readErr != nil {
			return result, errors.Join(ErrComputerCreationIncomplete, readErr)
		}
	}
	result.Complete = true
	return result, nil
}

package activedirectory

import (
	"context"
	"errors"
)

// CreateUser creates disabled, optionally resets the initial password, then
// enables only when explicitly requested. Enablement without password setup
// additionally requires explicit PasswordNotRequired=true. Stages are not a
// transaction; any accepted/uncertain stage stops on error and is never replayed.
func (c *Client) CreateUser(ctx context.Context, request CreateUserRequest) (result UserCreationResult, err error) {
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
		return result, ErrInvalidUser
	}
	if request.Class == "" {
		request.Class = "user"
	}
	if request.Class != "user" && request.Class != "inetOrgPerson" {
		return result, ErrInvalidUser
	}
	wantEnabled := request.Properties.Enabled != nil && *request.Properties.Enabled
	withoutPassword := request.Properties.PasswordNotRequired != nil && *request.Properties.PasswordNotRequired
	if wantEnabled && request.InitialPassword == nil && !withoutPassword {
		return result, ErrInvalidUser
	}
	if request.InitialPassword != nil {
		if err := validatePasswordBytes(request.InitialPassword); err != nil {
			return result, err
		}
	}
	// Validate text/raw conflicts before any stage. Directory-specific flag
	// mapping is finalized after reading the selected connection's RootDSE.
	if _, err := userCreationAttributes(request, DirectoryADDS); err != nil {
		return result, err
	}
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	var kind DirectoryType
	err = c.read(bounded, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		kind = root.Capabilities().Type
		if kind == DirectoryUnknown {
			return ErrUserCapability
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
		request.Parent, err = accountCreationParent(ctx, c.session, c.config, root, request.Parent, request.Options, wellKnownUsers)
		return err
	})
	if err != nil {
		return result, err
	}
	attributes, err := userCreationAttributes(request, kind)
	if err != nil {
		return result, err
	}
	request.Options.Properties = userProperties(request.Options.Properties)
	result.Creation, err = c.CreateObject(bounded, CreateObjectRequest{Parent: request.Parent, Class: request.Class, Name: request.Name, Attributes: attributes, Options: request.Options})
	if result.Creation.After != nil {
		user, decodeErr := decodeUser(*result.Creation.After)
		result.User = &user
		err = errors.Join(err, decodeErr)
	}
	if err != nil {
		return result, errors.Join(ErrUserCreationIncomplete, err)
	}
	if result.Creation.TargetGUID == nil || !result.Creation.Verified {
		return result, errors.Join(ErrUserCreationIncomplete, ErrObjectVerification)
	}
	account := objectGUIDIdentity(*result.Creation.TargetGUID)
	partition := result.Creation.Partition
	if request.InitialPassword != nil {
		password, passwordErr := c.ResetAccountPassword(bounded, PasswordResetRequest{Identity: account, Partition: partition, NewPassword: request.InitialPassword})
		result.Password = &password
		if passwordErr != nil || password.State != ObjectWriteAccepted {
			return result, errors.Join(ErrUserCreationIncomplete, passwordErr)
		}
	}
	if wantEnabled {
		enabled := true
		update, updateErr := c.UpdateUser(bounded, UpdateUserRequest{Identity: account, Properties: UserProperties{Enabled: &enabled}, Options: ObjectMutationOptions{Partition: partition, Properties: request.Options.Properties}})
		result.Enable = &update.Mutation
		if update.User != nil {
			result.User = update.User
		}
		if updateErr != nil || !update.Mutation.Verified {
			return result, errors.Join(ErrUserCreationIncomplete, updateErr)
		}
	} else if request.InitialPassword != nil {
		// Password setup can change server-maintained timestamps. Retain the
		// creation observation separately instead of presenting it as current.
		observation, readErr := c.User(bounded, account, ResolveIdentityOptions{Partition: partition, Properties: request.Options.Properties})
		result.Observation = &observation
		if observation.User != nil {
			result.User = observation.User
		}
		if readErr != nil {
			return result, errors.Join(ErrUserCreationIncomplete, readErr)
		}
	}
	result.Complete = true
	return result, nil
}

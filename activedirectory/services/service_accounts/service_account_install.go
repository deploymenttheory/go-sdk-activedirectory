package service_accounts

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func (c *Service) InstallLocalServiceAccount(
	ctx context.Context,
	request InstallLocalServiceAccountRequest,
) (LocalServiceAccountResult, error) {
	return internalServiceInstallLocalServiceAccount(c,
		ctx,
		request,
		admodel.InternalNewLocalServiceAccountBackend(),
	)
}

func (c *Service) UninstallLocalServiceAccount(
	ctx context.Context,
	request UninstallLocalServiceAccountRequest,
) (LocalServiceAccountResult, error) {
	return InternalServiceUninstallLocalServiceAccount(c,
		ctx,
		request,
		admodel.InternalNewLocalServiceAccountBackend(),
	)
}

func internalServicePrepareLocalServiceAccount(c *Service,
	ctx context.Context,
	backend admodel.InternalLocalServiceAccountBackend,
	identity admodel.Identity,
	partition string,
	install, force bool,
	result *admodel.LocalServiceAccountResult,
) error {
	options := admodel.InternalAccountControlIdentity(
		identity,
		partition,
		[]string{"objectClass", "objectGUID", "objectSid", "name", "sAMAccountName", "uSNChanged"},
	)
	if err := admodel.InternalValidateIdentityOperation(identity, options); err != nil {
		return err
	}
	var err error
	result.Host, err = backend.InternalHost(ctx)
	if err != nil {
		return err
	}
	if result.Host.ComputerName == "" || result.Host.DomainGUID == (admodel.GUID{}) ||
		result.Host.ReadOnly ||
		(result.Host.MachineRole != 1 && result.Host.MachineRole != 3 && result.Host.MachineRole != 4 && result.Host.MachineRole != 5) {
		return admodel.ErrServiceAccountHost
	}
	return adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		if err = root.Capabilities().RequireADDS("LocalServiceAccount"); err != nil {
			return err
		}
		if adengine.InternalClientConfig(c.engine()).Endpoint.Port == 3268 ||
			adengine.InternalClientConfig(c.engine()).Endpoint.Port == 3269 {
			return admodel.ErrServiceAccountHost
		}
		result.Directory, err = admodel.InternalResolveIdentitySession(
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
		account, err := admodel.InternalDecodeServiceAccount(*result.Directory.Object)
		result.Account = &account
		if err != nil {
			return err
		}
		if account.SAMAccountName == nil {
			return admodel.ErrAttributeUnavailable
		}
		result.NativeAccountName, err = admodel.InternalLocalServiceAccountName(
			*account.SAMAccountName,
		)
		if err != nil {
			return err
		}
		domain, err := admodel.IdentityByDN(result.Directory.Partition)
		if err != nil {
			return err
		}
		result.Domain, err = admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			domain,
			admodel.ResolveIdentityOptions{
				Partition:  result.Directory.Partition,
				Properties: []string{"objectGUID", "objectClass"},
			},
		)
		if err != nil {
			return err
		}
		value, err := result.Domain.Object.Values("objectGUID").Single()
		if err != nil {
			return err
		}
		guid, err := value.GUID()
		if err != nil {
			return err
		}
		if guid != result.Host.DomainGUID {
			return admodel.ErrServiceAccountHost
		}
		if install && account.Kind == admodel.ServiceAccountStandalone {
			hostID, err := admodel.IdentityByAccountName(result.Host.ComputerName + "$")
			if err != nil {
				return err
			}
			result.HostComputer, err = admodel.InternalResolveIdentitySession(
				ctx,
				adengine.InternalClientSession(c.engine()),
				adengine.InternalClientConfig(c.engine()),
				root,
				hostID,
				admodel.InternalComputerIdentityOptions(hostID, result.Directory.Partition, nil),
			)
			if err != nil {
				return err
			}
			if err = admodel.InternalComputerClass(*result.HostComputer.Object); err != nil {
				return err
			}
			if err = admodel.InternalCollectLocalServiceAccountHosts(
				ctx,
				adengine.InternalClientSession(c.engine()),
				result,
			); err != nil {
				return err
			}
			if len(result.OtherHosts) > 0 && !force {
				return admodel.ErrServiceAccountOtherHost
			}
		}
		result.Prepared = true
		return nil
	})
}

func internalServiceInstallLocalServiceAccount(c *Service,
	ctx context.Context,
	request admodel.InstallLocalServiceAccountRequest,
	backend admodel.InternalLocalServiceAccountBackend,
) (result admodel.LocalServiceAccountResult, err error) {
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	if ctx == nil {
		return result, admodel.ErrInvalidServiceAccountInstall
	}
	bounded, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()
	if err = admodel.InternalLockLocalServiceAccount(bounded); err != nil {
		return
	}
	defer func() { <-admodel.InternalLocalServiceAccountGate }()
	if err = internalServicePrepareLocalServiceAccount(c,
		bounded,
		backend,
		request.Identity,
		request.Partition,
		true,
		request.Force,
		&result,
	); err != nil {
		return
	}
	result.Before, err = backend.InternalInstalled(bounded, result.NativeAccountName)
	if err != nil {
		return
	}
	if result.Before == nil {
		return result, admodel.ErrInvalidResult
	}
	result.Preview = request.Preview
	result.PasswordOptionsIgnored = result.Account.Kind == admodel.ServiceAccountGroupManaged &&
		(request.AccountPassword != nil || request.PasswordPrompt != nil)
	if request.Preview {
		result.Complete = true
		return
	}
	var password []byte
	flags := uint32(1)
	if result.Account.Kind == admodel.ServiceAccountStandalone {
		password = request.AccountPassword
		if password == nil && request.PasswordPrompt != nil {
			password, err = request.PasswordPrompt(bounded, *result.Account)
			defer clear(password)
			if err != nil {
				return
			}
			if password == nil {
				return result, admodel.ErrInvalidServiceAccountInstall
			}
		}
		if password != nil {
			if err = admodel.InternalValidatePasswordBytes(password); err != nil {
				return
			}
			flags = 2
		}
	}
	if err = context.Cause(bounded); err != nil {
		return
	}
	attempt := backend.InternalInstall(bounded, result.NativeAccountName, password, flags)
	result.Attempts = append(result.Attempts, attempt)
	result.PartialEffectsPossible = attempt.State != admodel.ObjectWriteNotAttempted
	if err = admodel.InternalLocalServiceAccountAttemptError(attempt); err != nil {
		return result, errors.Join(err, context.Cause(bounded))
	}
	result.After, err = backend.InternalInstalled(bounded, result.NativeAccountName)
	if err != nil {
		return result, errors.Join(admodel.ErrServiceAccountLocalObservation, err)
	}
	result.Verified = result.After != nil && *result.After
	result.Complete = result.Verified
	if !result.Verified {
		return result, admodel.ErrServiceAccountLocalObservation
	}
	return
}

func InternalServiceUninstallLocalServiceAccount(c *Service,
	ctx context.Context,
	request admodel.UninstallLocalServiceAccountRequest,
	backend admodel.InternalLocalServiceAccountBackend,
) (result admodel.LocalServiceAccountResult, err error) {
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	if ctx == nil {
		return result, admodel.ErrInvalidServiceAccountInstall
	}
	bounded, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()
	if err = admodel.InternalLockLocalServiceAccount(bounded); err != nil {
		return
	}
	defer func() { <-admodel.InternalLocalServiceAccountGate }()
	if err = internalServicePrepareLocalServiceAccount(c,
		bounded,
		backend,
		request.Identity,
		request.Partition,
		false,
		false,
		&result,
	); err != nil {
		return
	}
	result.Before, err = backend.InternalInstalled(bounded, result.NativeAccountName)
	if err != nil {
		return
	}
	if result.Before == nil {
		return result, admodel.ErrInvalidResult
	}
	result.Preview = request.Preview
	if request.Preview {
		result.Complete = true
		return
	}
	if err = context.Cause(bounded); err != nil {
		return
	}
	attempt := backend.InternalUninstall(bounded, result.NativeAccountName, 1)
	result.Attempts = append(result.Attempts, attempt)
	result.PartialEffectsPossible = attempt.State != admodel.ObjectWriteNotAttempted
	err = admodel.InternalLocalServiceAccountAttemptError(attempt)
	if request.ForceRemoveLocal && attempt.State == admodel.ObjectWriteRejected &&
		attempt.Error == nil &&
		attempt.Status != nil &&
		*attempt.Status == 0xc00000df &&
		context.Cause(bounded) == nil {
		// This is an explicit, different offline phase after a known reply; it
		// is never used to repeat an unknown or interrupted online operation.
		attempt = backend.InternalUninstall(bounded, result.NativeAccountName, 2)
		result.Attempts = append(result.Attempts, attempt)
		result.PartialEffectsPossible = result.PartialEffectsPossible ||
			attempt.State != admodel.ObjectWriteNotAttempted
		err = admodel.InternalLocalServiceAccountAttemptError(attempt)
	}
	if err != nil {
		return result, errors.Join(err, context.Cause(bounded))
	}
	result.After, err = backend.InternalInstalled(bounded, result.NativeAccountName)
	if err != nil {
		return result, errors.Join(admodel.ErrServiceAccountLocalObservation, err)
	}
	// The native presence reading does not track uninstall for a group managed
	// account. The lab observed NetIsServiceAccount still reporting true after
	// a successful uninstall, because for a gMSA the reading follows this
	// host's eligibility to use the account rather than local installation.
	// See docs/research/local-service-accounts.md. Requiring the flip would
	// turn every successful gMSA uninstall into an observation error, so the
	// operation completes unverified and says so rather than failing.
	if result.Account != nil && result.Account.Kind == admodel.ServiceAccountGroupManaged {
		result.Verified = false
		result.Complete = true
		return
	}
	result.Verified = result.After != nil && !*result.After
	result.Complete = result.Verified
	if !result.Verified {
		return result, admodel.ErrServiceAccountLocalObservation
	}
	return
}

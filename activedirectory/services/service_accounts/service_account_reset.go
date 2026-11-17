package service_accounts

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// ResetLocalServiceAccountPassword mirrors Reset-ADServiceAccountPassword
// (issue #49). It refreshes the credential this host holds; it is not a
// directory password reset and takes no password from the caller.
//
// # Evidence and its limits
//
// The lab established the contract: the reference refuses on an account that
// is not installed on this computer, both before an install and after an
// uninstall, and succeeds on an installed one. That makes it a local
// operation against installed host state.
//
// The native call this uses — NetAddServiceAccount with a NULL password on an
// installed account — returned NTSTATUS 0 in exactly the state where the
// reference succeeded, and the observable state afterwards was identical to
// the reference's. That is **consistent with** the reference performing this
// call; it is not proof, because no observable value distinguishes the two.
// The operation therefore stays `unverified` in the coverage contract. See
// docs/research/local-service-accounts.md.
func (c *Service) ResetLocalServiceAccountPassword(
	ctx context.Context,
	request ResetLocalServiceAccountPasswordRequest,
) (LocalServiceAccountResult, error) {
	return InternalServiceResetLocalServiceAccountPassword(c,
		ctx,
		request,
		admodel.InternalNewLocalServiceAccountBackend(),
	)
}

func InternalServiceResetLocalServiceAccountPassword(c *Service,
	ctx context.Context,
	request admodel.ResetLocalServiceAccountPasswordRequest,
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
		return result, err
	}
	defer func() { <-admodel.InternalLocalServiceAccountGate }()

	// A reset is not an install: no standalone other-host check applies, so
	// force stays false and install is false.
	if err = internalServicePrepareLocalServiceAccount(c,
		bounded,
		backend,
		request.Identity,
		request.Partition,
		false,
		false,
		&result,
	); err != nil {
		return result, err
	}

	result.Before, err = backend.InternalInstalled(bounded, result.NativeAccountName)
	if err != nil {
		return result, err
	}
	if result.Before == nil {
		// An unknown reading is never treated as installed. Resetting on an
		// unknown state could act on an account this host does not hold.
		return result, admodel.ErrInvalidResult
	}
	if !*result.Before {
		return result, admodel.ErrServiceAccountNotInstalled
	}

	result.Preview = request.Preview
	if request.Preview {
		result.Complete = true
		return result, nil
	}
	if err = context.Cause(bounded); err != nil {
		return result, err
	}

	// A NULL password with flags 1 asks the host to manage the credential.
	// The backend rejects a password alongside these flags, so a caller
	// cannot smuggle one in through this path.
	attempt := backend.InternalInstall(bounded, result.NativeAccountName, nil, 1)
	result.Attempts = append(result.Attempts, attempt)
	result.PartialEffectsPossible = attempt.State != admodel.ObjectWriteNotAttempted
	if err = admodel.InternalLocalServiceAccountAttemptError(attempt); err != nil {
		return result, errors.Join(err, context.Cause(bounded))
	}

	result.After, err = backend.InternalInstalled(bounded, result.NativeAccountName)
	if err != nil {
		return result, errors.Join(admodel.ErrServiceAccountLocalObservation, err)
	}
	// The account must still be installed afterwards. A reset that left it
	// absent would be an uninstall, not a reset.
	result.Verified = result.After != nil && *result.After
	result.Complete = result.Verified
	if !result.Verified {
		return result, admodel.ErrServiceAccountLocalObservation
	}
	return result, nil
}

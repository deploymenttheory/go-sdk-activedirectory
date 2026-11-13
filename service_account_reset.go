package activedirectory

import (
	"context"
	"errors"
)

// ErrServiceAccountNotInstalled mirrors the reference refusal observed in the
// lab: "Referenced service account is not installed on this computer".
var ErrServiceAccountNotInstalled = errors.New("service account is not installed on this computer")

// ResetLocalServiceAccountPasswordRequest resets the host-held credential for
// one managed service account that is already installed here.
type ResetLocalServiceAccountPasswordRequest struct {
	Identity  Identity
	Partition string
	// Preview performs read-only preparation and the installed-state check
	// without calling the native reset.
	Preview bool
}

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
func (c *Client) ResetLocalServiceAccountPassword(ctx context.Context, request ResetLocalServiceAccountPasswordRequest) (LocalServiceAccountResult, error) {
	return c.resetLocalServiceAccountPassword(ctx, request, newLocalServiceAccountBackend())
}

func (c *Client) resetLocalServiceAccountPassword(ctx context.Context, request ResetLocalServiceAccountPasswordRequest, backend localServiceAccountBackend) (result LocalServiceAccountResult, err error) {
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	if ctx == nil {
		return result, ErrInvalidServiceAccountInstall
	}
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	if err = lockLocalServiceAccount(bounded); err != nil {
		return result, err
	}
	defer func() { <-localServiceAccountGate }()

	// A reset is not an install: no standalone other-host check applies, so
	// force stays false and install is false.
	if err = c.prepareLocalServiceAccount(bounded, backend, request.Identity, request.Partition, false, false, &result); err != nil {
		return result, err
	}

	result.Before, err = backend.installed(bounded, result.NativeAccountName)
	if err != nil {
		return result, err
	}
	if result.Before == nil {
		// An unknown reading is never treated as installed. Resetting on an
		// unknown state could act on an account this host does not hold.
		return result, ErrInvalidResult
	}
	if !*result.Before {
		return result, ErrServiceAccountNotInstalled
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
	attempt := backend.install(bounded, result.NativeAccountName, nil, 1)
	result.Attempts = append(result.Attempts, attempt)
	result.PartialEffectsPossible = attempt.State != ObjectWriteNotAttempted
	if err = localServiceAccountAttemptError(attempt); err != nil {
		return result, errors.Join(err, context.Cause(bounded))
	}

	result.After, err = backend.installed(bounded, result.NativeAccountName)
	if err != nil {
		return result, errors.Join(ErrServiceAccountLocalObservation, err)
	}
	// The account must still be installed afterwards. A reset that left it
	// absent would be an uninstall, not a reset.
	result.Verified = result.After != nil && *result.After
	result.Complete = result.Verified
	if !result.Verified {
		return result, ErrServiceAccountLocalObservation
	}
	return result, nil
}

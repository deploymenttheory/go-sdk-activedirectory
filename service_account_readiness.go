package activedirectory

import (
	"context"
	"errors"
)

// Readiness mirrors Test-ADServiceAccount (issue #48).
//
// The reference reports whether this host can use the account, **not** whether
// the account is installed locally. In the lab a group managed account reported
// ready before it was ever installed and still ready after it was uninstalled,
// while a standalone account with a host association but no successful install
// reported not ready. Across every observed state the reference's result
// matched the native NetIsServiceAccount boolean exactly, so that is the
// reading this mirrors. See docs/research/local-service-accounts.md.

var ErrServiceAccountReadiness = errors.New("service account readiness could not be determined")

// ServiceAccountReadinessRequest selects one account. The account is resolved
// over the configured LDAP endpoint; the readiness reading is taken on the
// executing host.
type ServiceAccountReadinessRequest struct {
	Identity  Identity
	Partition string
}

// ServiceAccountReadinessResult reports the reading and everything it was
// derived from, so a false result is explainable rather than bare.
type ServiceAccountReadinessResult struct {
	Host      LocalServiceAccountHost
	Directory IdentityResult
	Domain    IdentityResult
	Account   *ServiceAccount
	// NativeAccountName is the name passed to the native API, without the
	// trailing dollar the directory stores.
	NativeAccountName string
	// Ready is the host's own answer. It is nil when the native reading did
	// not complete; an unknown reading is never reported as not ready.
	Ready *bool
	// Observed records that the native call completed and Ready is its result.
	Observed bool
}

// ServiceAccountReadiness reports whether the executing host can use one
// managed service account.
//
// A nil Ready with no error cannot happen: an incomplete reading is an error,
// because silently returning "not ready" would be indistinguishable from a
// genuine negative and could send a caller to reinstall a working account.
func (c *Client) ServiceAccountReadiness(ctx context.Context, request ServiceAccountReadinessRequest) (ServiceAccountReadinessResult, error) {
	return c.serviceAccountReadiness(ctx, request, newLocalServiceAccountBackend())
}

func (c *Client) serviceAccountReadiness(ctx context.Context, request ServiceAccountReadinessRequest, backend localServiceAccountBackend) (result ServiceAccountReadinessResult, err error) {
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	if ctx == nil {
		return result, ErrInvalidServiceAccountInstall
	}
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// Readiness is a read. It still takes the local gate so it cannot observe
	// a half-applied state while this process is installing or uninstalling.
	if err = lockLocalServiceAccount(bounded); err != nil {
		return result, err
	}
	defer func() { <-localServiceAccountGate }()

	// Reuse the install preparation so the host/account domain agreement and
	// identity resolution are identical to the operations this informs. No
	// standalone other-host check applies to a read, so Force stays false.
	var prepared LocalServiceAccountResult
	if err = c.prepareLocalServiceAccount(bounded, backend, request.Identity, request.Partition, false, false, &prepared); err != nil {
		return result, err
	}
	result.Host = prepared.Host
	result.Directory = prepared.Directory
	result.Domain = prepared.Domain
	result.Account = prepared.Account
	result.NativeAccountName = prepared.NativeAccountName

	reading, err := backend.installed(bounded, result.NativeAccountName)
	if err != nil {
		return result, errors.Join(ErrServiceAccountReadiness, err)
	}
	if reading == nil {
		return result, ErrServiceAccountReadiness
	}
	result.Ready = reading
	result.Observed = true
	return result, nil
}

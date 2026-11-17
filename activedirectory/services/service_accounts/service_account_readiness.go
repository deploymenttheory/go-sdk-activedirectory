package service_accounts

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// ServiceAccountReadiness reports whether the executing host can use one
// managed service account.
//
// A nil Ready with no error cannot happen: an incomplete reading is an error,
// because silently returning "not ready" would be indistinguishable from a
// genuine negative and could send a caller to reinstall a working account.
func (c *Service) ServiceAccountReadiness(
	ctx context.Context,
	request ServiceAccountReadinessRequest,
) (ServiceAccountReadinessResult, error) {
	return InternalServiceServiceAccountReadiness(c,
		ctx,
		request,
		admodel.InternalNewLocalServiceAccountBackend(),
	)
}

func InternalServiceServiceAccountReadiness(c *Service,
	ctx context.Context,
	request admodel.ServiceAccountReadinessRequest,
	backend admodel.InternalLocalServiceAccountBackend,
) (result admodel.ServiceAccountReadinessResult, err error) {
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	if ctx == nil {
		return result, admodel.ErrInvalidServiceAccountInstall
	}
	bounded, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()

	// Readiness is a read. It still takes the local gate so it cannot observe
	// a half-applied state while this process is installing or uninstalling.
	if err = admodel.InternalLockLocalServiceAccount(bounded); err != nil {
		return result, err
	}
	defer func() { <-admodel.InternalLocalServiceAccountGate }()

	// Reuse the install preparation so the host/account domain agreement and
	// identity resolution are identical to the operations this informs. No
	// standalone other-host check applies to a read, so Force stays false.
	var prepared admodel.LocalServiceAccountResult
	if err = internalServicePrepareLocalServiceAccount(c,
		bounded,
		backend,
		request.Identity,
		request.Partition,
		false,
		false,
		&prepared,
	); err != nil {
		return result, err
	}
	result.Host = prepared.Host
	result.Directory = prepared.Directory
	result.Domain = prepared.Domain
	result.Account = prepared.Account
	result.NativeAccountName = prepared.NativeAccountName

	reading, err := backend.InternalInstalled(bounded, result.NativeAccountName)
	if err != nil {
		return result, errors.Join(admodel.ErrServiceAccountReadiness, err)
	}
	if reading == nil {
		return result, admodel.ErrServiceAccountReadiness
	}
	result.Ready = reading
	result.Observed = true
	return result, nil
}

package engine

import (
	"context"
	"errors"
	"time"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// InternalMoveSecurity observes the established source context, never requested
// configuration. Local forwarding does not prove the DC's remote authorization.
func (s *InternalPortableSession) InternalMoveSecurity(ctx context.Context) (admodel.MoveSecurity, error) {
	observed, err := s.InternalSessionProtection(ctx)
	result := admodel.MoveSecurity{Protection: observed, Delegated: observed.Delegated}
	if err != nil {
		return result, errors.Join(admodel.ErrMoveDelegation, err)
	}
	if observed.Authentication == admodel.AuthenticationKerberos {
		result.Package = "Kerberos"
	}
	protected := observed.TLSVerified && observed.CipherBits >= 128 || observed.SASLProtection == admodel.SASLProtectionSign ||
		observed.SASLProtection == admodel.SASLProtectionSeal && observed.SASLCipherBits >= 128
	if !observed.Complete || observed.Backend != admodel.BackendPortable || result.Package == "" || !observed.MutualAuthentication ||
		!observed.Delegated || !observed.DelegationSent || observed.DelegationExpiresAt.IsZero() || !time.Now().Before(observed.DelegationExpiresAt) || !protected {
		return result, admodel.ErrMoveDelegation
	}
	result.Complete = true
	return result, nil
}

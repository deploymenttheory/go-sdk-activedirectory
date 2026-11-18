package engine

import (
	"context"
	"errors"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func InternalDialBackend(ctx context.Context, config admodel.Config) (admodel.InternalDirectorySession, error) {
	if config.Backend == admodel.BackendPortable {
		if config.Authentication == admodel.AuthenticationNegotiate {
			return nil, &admodel.BackendUnavailableError{
				Backend: config.Backend, Authentication: config.Authentication, Feature: "Windows integrated authentication",
			}
		}
		return InternalDialPortable(ctx, config)
	}
	if config.Authentication == admodel.AuthenticationKerberos || config.TLS != nil || config.SASLProtection != admodel.SASLProtectionDefault {
		return nil, &admodel.BackendUnavailableError{
			Backend: config.Backend, Authentication: config.Authentication, Feature: "the requested authentication or protection options",
		}
	}
	session, err := InternalDialNative(ctx, config)
	if errors.Is(err, admodel.ErrUnsupported) && !errors.Is(err, admodel.ErrUnsupportedDirectory) {
		err = errors.Join(&admodel.BackendUnavailableError{
			Backend: config.Backend, Authentication: config.Authentication, Feature: "the required native host mechanism",
		}, err)
	}
	return session, err
}

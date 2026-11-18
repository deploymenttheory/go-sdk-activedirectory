package engine

import (
	"context"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// InternalDialPortable refuses an implementation not yet qualified for use.
// SDK-02 owns the portable session; declaring a contract is not protocol support.
func InternalDialPortable(_ context.Context, config admodel.Config) (admodel.InternalDirectorySession, error) {
	return nil, &admodel.BackendUnavailableError{
		Backend: admodel.BackendPortable, Authentication: config.Authentication, Feature: "portable LDAP execution",
	}
}

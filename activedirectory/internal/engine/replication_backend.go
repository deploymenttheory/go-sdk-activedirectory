package engine

import (
	"context"
	"fmt"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type internalReplicationRead func(
	context.Context,
	admodel.Config,
	admodel.RootDSE,
	[]byte,
	admodel.InternalReplicationRequest,
) (map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, error)

// InternalReadReplicationBackend selects the explicitly configured diagnostics
// backend. Portable RPC remains unavailable until its protocol/security gate
// passes; it never invokes Windows APIs or substitutes LDAP failure/queue data.
func InternalReadReplicationBackend(
	ctx context.Context,
	config admodel.Config,
	root admodel.RootDSE,
	instance []byte,
	request admodel.InternalReplicationRequest,
) (map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, error) {
	return internalReadReplicationBackend(ctx, config, root, instance, request, InternalReadReplicationNative)
}

func internalReadReplicationBackend(
	ctx context.Context,
	config admodel.Config,
	root admodel.RootDSE,
	instance []byte,
	request admodel.InternalReplicationRequest,
	native internalReplicationRead,
) (map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, error) {
	config, err := admodel.InternalConfigNormalized(config)
	if err != nil {
		return nil, err
	}
	if cause := context.Cause(ctx); cause != nil {
		return nil, fmt.Errorf("select replication backend: %w", cause)
	}
	if len(request.InternalKinds) == 0 {
		return make(map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply), nil
	}
	if err := internalReplicationAuthentication(config); err != nil {
		return nil, err
	}
	if config.Backend == admodel.BackendPortable {
		return nil, &admodel.BackendUnavailableError{
			Backend: config.Backend, Authentication: config.Authentication,
			Feature: "portable authenticated DRS/RPC diagnostics pending qualification",
		}
	}
	return native(ctx, config, root, instance, request)
}

func internalReplicationAuthentication(config admodel.Config) error {
	if config.Backend == admodel.BackendPortable {
		if config.Authentication != admodel.AuthenticationKerberos {
			return fmt.Errorf("%w: portable replication RPC requires explicit Kerberos authentication", admodel.ErrInvalidConfig)
		}
		return nil
	}
	if config.Authentication != admodel.AuthenticationNegotiate {
		return fmt.Errorf("%w: native replication RPC requires Negotiate authentication", admodel.ErrInvalidConfig)
	}
	return admodel.InternalValidateReplicationCredentials(config.Credentials)
}

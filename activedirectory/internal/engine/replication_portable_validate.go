package engine

import (
	"bytes"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func internalReplicationPortableRequest(
	config admodel.Config,
	root admodel.RootDSE,
	instance []byte,
	request admodel.InternalReplicationRequest,
	dialer InternalPortableDialer,
) error {
	if config.Backend != admodel.BackendPortable || config.Authentication != admodel.AuthenticationKerberos || dialer == nil {
		return admodel.ErrInvalidConfig
	}
	if root.Capabilities().Type != admodel.DirectoryADDS {
		return admodel.ErrUnsupportedDirectory
	}
	if len(request.InternalKinds) == 0 {
		return nil
	}
	seen := make(map[admodel.InternalReplicationInfo]bool, len(request.InternalKinds))
	for _, kind := range request.InternalKinds {
		if kind != admodel.InternalReplicationNeighbors && kind != admodel.InternalReplicationConnectFailures && kind != admodel.InternalReplicationLinkFailures &&
			kind != admodel.InternalReplicationPendingOperations ||
			seen[kind] {
			return admodel.ErrInvalidReplicationQuery
		}
		seen[kind] = true
	}
	if request.InternalServicePrincipals == nil || request.InternalPortableIdentity == nil || !bytes.Equal(instance, request.InternalPortableIdentity.DSA[:]) {
		return admodel.ErrInvalidConfig
	}
	return internalValidateReplicationServiceIdentity(config, root, *request.InternalServicePrincipals, *request.InternalPortableIdentity)
}

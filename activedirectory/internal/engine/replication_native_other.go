//go:build !windows || (!amd64 && !arm64)

package engine

import (
	"context"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func InternalReadReplicationNative(
	context.Context,
	admodel.Config,
	admodel.RootDSE,
	[]byte,
	admodel.InternalReplicationRequest,
) (map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, error) {
	return nil, admodel.ErrUnsupported
}

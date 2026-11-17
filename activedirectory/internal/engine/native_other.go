//go:build !windows || (!amd64 && !arm64)

package engine

import (
	"context"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func InternalDialNative(context.Context, admodel.Config) (admodel.InternalDirectorySession, error) {
	return nil, admodel.ErrUnsupported
}

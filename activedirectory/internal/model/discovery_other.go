//go:build !windows || (!amd64 && !arm64)

package model

import "context"

func InternalDiscoverDomainControllerNative(
	context.Context,
	DiscoveryOptions,
) (DiscoveredController, error) {
	return DiscoveredController{}, ErrUnsupported
}

func InternalCurrentDomainNative(context.Context, CurrentMode) (DomainName, error) {
	return DomainName{}, ErrUnsupported
}

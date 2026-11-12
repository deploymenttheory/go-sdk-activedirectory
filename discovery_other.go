//go:build !windows || (!amd64 && !arm64)

package activedirectory

import "context"

func discoverDomainControllerNative(context.Context, DiscoveryOptions) (DiscoveredController, error) {
	return DiscoveredController{}, ErrUnsupported
}

func currentDomainNative(context.Context, CurrentMode) (DomainName, error) {
	return DomainName{}, ErrUnsupported
}

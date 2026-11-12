//go:build !windows || (!amd64 && !arm64)

package activedirectory

import (
	"context"
	"errors"
	"testing"
)

func TestDiscoveryRequiresSupportedWindowsHost(t *testing.T) {
	if _, err := DiscoverDomainController(context.Background(), DiscoveryOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	for _, mode := range []CurrentMode{CurrentLocalComputer, CurrentLoggedOnUser} {
		if _, err := CurrentDomain(context.Background(), mode); !errors.Is(err, ErrUnsupported) {
			t.Fatal(err)
		}
	}
}

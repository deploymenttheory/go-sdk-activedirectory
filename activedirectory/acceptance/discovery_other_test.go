//go:build !windows || (!amd64 && !arm64)

package acceptance

import (
	"context"
	"errors"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestDiscoveryRequiresSupportedWindowsHost(t *testing.T) {
	if _, err := admodel.DiscoverDomainController(
		context.Background(),
		admodel.DiscoveryOptions{},
	); !errors.Is(
		err,
		admodel.ErrUnsupported,
	) {
		t.Fatal(err)
	}
	for _, mode := range []admodel.CurrentMode{admodel.CurrentLocalComputer, admodel.CurrentLoggedOnUser} {
		if _, err := admodel.CurrentDomain(
			context.Background(),
			mode,
		); !errors.Is(
			err,
			admodel.ErrUnsupported,
		) {
			t.Fatal(err)
		}
	}
}

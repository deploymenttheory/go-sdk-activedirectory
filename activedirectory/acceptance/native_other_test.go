//go:build !windows || (!amd64 && !arm64)

package acceptance

import (
	"context"
	"errors"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestDialUnsupportedPlatform(t *testing.T) {
	client, err := adengine.Dial(
		context.Background(),
		admodel.Config{Endpoint: admodel.Endpoint{Host: "dc1.ad.sdk.test"}},
	)
	if client != nil || !errors.Is(err, admodel.ErrUnsupported) {
		t.Fatalf("Dial = %v, %v", client, err)
	}
}

//go:build windows && (amd64 || arm64)

package acceptance

import (
	"errors"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// Exercise the actual WinLDAP RootDSE read against an owned local wire fixture.
// This proves refusal and native resource cleanup, not live AD qualification.
func TestNativeTypedReadDirectoryRefusals(t *testing.T) {
	for _, target := range InternalEndpointSweepTargets() {
		if target.InternalCmdlet == "Get-ADObject" {
			continue
		}
		t.Run(target.InternalCmdlet, func(t *testing.T) {
			fixture := InternalNewSearchWireFixture(t, []InternalSearchWirePage{{InternalBaseRead: true}})
			var counts InternalSearchNativeCounts
			client := InternalSearchWireClient(t, fixture, InternalCountedSearchAPI(&counts))
			result, err := target.InternalRead(t.Context(), client, admodel.SearchOptions{})
			var capability *admodel.DirectoryCapabilityError
			if !errors.Is(err, admodel.ErrUnsupportedDirectory) || !errors.As(err, &capability) || result.Complete {
				t.Fatalf("native directory refusal: %v, complete=%v", err, result.Complete)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if remaining := InternalSweepAllocations(counts); remaining != 0 {
				t.Fatalf("native resources retained: %d", remaining)
			}
		})
	}
}

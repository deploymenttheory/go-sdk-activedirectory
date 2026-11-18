package acceptance

import (
	"context"
	"errors"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestTypedReadsDistinguishDirectoryRefusalFromUnavailableBackend(t *testing.T) {
	for _, target := range InternalEndpointSweepTargets() {
		if target.InternalCmdlet == "Get-ADObject" {
			continue // Generic search deliberately has no AD directory prerequisite.
		}
		t.Run(target.InternalCmdlet, func(t *testing.T) {
			reads, closes := 0, 0
			client := adengine.InternalNewClient(admodel.Config{Timeout: time.Second}, InternalTestSession{
				InternalBase: func(_ context.Context, base string, _ []string) (map[string][][]byte, error) {
					reads++
					if base != "" {
						t.Fatal("directory refusal reached an object read")
					}
					return map[string][][]byte{}, nil
				},
				InternalSearch: func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					t.Fatal("directory refusal reached a search")
					return nil, admodel.ErrClosed
				},
				InternalFinish: func() error { closes++; return nil },
			})
			t.Cleanup(func() {
				if err := client.Close(); err != nil || closes != 1 {
					t.Errorf("close: %v, calls=%d", err, closes)
				}
			})
			for range 3 {
				result, err := target.InternalRead(t.Context(), client, admodel.SearchOptions{})
				var capability *admodel.DirectoryCapabilityError
				if !errors.Is(err, admodel.ErrUnsupportedDirectory) || !errors.As(err, &capability) {
					t.Fatalf("directory refusal is not distinguishable: %v", err)
				}
				if capability.Operation == "" || capability.Actual != admodel.DirectoryUnknown || result.Complete {
					t.Fatalf("imprecise refusal: %+v, complete=%v", capability, result.Complete)
				}
				if !errors.Is(err, admodel.ErrUnsupported) || admodel.Classify(err) != admodel.ClassUnsupported {
					t.Fatalf("legacy unsupported matching/classification lost: %v", err)
				}
			}
			if reads != 3 {
				t.Fatalf("unexpected capability reads or replay: %d", reads)
			}
		})
	}
}

func TestBackendUnsupportedDoesNotClaimWrongDirectory(t *testing.T) {
	if errors.Is(admodel.ErrUnsupported, admodel.ErrUnsupportedDirectory) {
		t.Fatal("backend unavailability claims a directory-type refusal")
	}
	var capability *admodel.DirectoryCapabilityError
	if errors.As(admodel.ErrUnsupported, &capability) {
		t.Fatal("backend unavailability contains a directory capability error")
	}
}

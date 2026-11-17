package acceptance

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestDirectoryCapabilitiesAndADDSGuard(t *testing.T) {
	for _, tc := range []struct {
		InternalName string
		InternalOids []string
		InternalWant admodel.DirectoryType
	}{
		{"unknown", []string{"1.2.3.999"}, admodel.DirectoryUnknown},
		{"missing", nil, admodel.DirectoryUnknown},
		{"ds", []string{admodel.CapabilityActiveDirectory}, admodel.DirectoryADDS},
		{"lds", []string{admodel.CapabilityADLDS}, admodel.DirectoryADLDS},
		{"lds-and-generic", []string{admodel.CapabilityActiveDirectory, admodel.CapabilityADLDS, "1.2.3.999"}, admodel.DirectoryADLDS},
	} {
		t.Run(tc.InternalName, func(t *testing.T) {
			root := admodel.RootDSE{SupportedCapabilities: slices.Clone(tc.InternalOids)}
			capabilities := root.Capabilities()
			if capabilities.Type != tc.InternalWant ||
				!slices.Equal(capabilities.OIDs, tc.InternalOids) {
				t.Fatalf("capabilities=%+v", capabilities)
			}
			err := capabilities.RequireADDS("domain operation")
			if tc.InternalWant == admodel.DirectoryADDS {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var prerequisite *admodel.DirectoryCapabilityError
				if !errors.Is(err, admodel.ErrUnsupportedDirectory) ||
					!errors.As(err, &prerequisite) ||
					prerequisite.Required != admodel.DirectoryADDS ||
					prerequisite.Actual != tc.InternalWant ||
					!strings.Contains(err.Error(), tc.InternalWant.String()) {
					t.Fatalf("imprecise guard error: %v", err)
				}
			}
			if len(capabilities.OIDs) != 0 {
				capabilities.OIDs[0] = "changed"
				if !slices.Equal(root.SupportedCapabilities, tc.InternalOids) {
					t.Fatal("capability slice aliases RootDSE")
				}
			}
		})
	}
}

func TestClientGuardNeverUsesFailedCapabilityRead(t *testing.T) {
	denied := &admodel.LDAPError{Operation: "capabilities", Code: 50}
	for _, readErr := range []error{nil, denied} {
		client := adengine.InternalNewClient(
			admodel.Config{Timeout: time.Second},
			InternalTestSession{
				InternalBase: func(_ context.Context, base string, properties []string) (map[string][][]byte, error) {
					if base != "" || !slices.Equal(properties, []string{"supportedCapabilities"}) {
						t.Fatal("unexpected capability read")
					}
					return map[string][][]byte{
						"supportedcapabilities": {
							[]byte(admodel.CapabilityActiveDirectory),
							[]byte(admodel.CapabilityADLDS),
						},
					}, readErr
				},
				InternalFinish: func() error { return nil },
			},
		)
		err := client.RequireADDS(context.Background(), "domain operation")
		_ = client.Close()
		want := readErr
		if want == nil {
			want = admodel.ErrUnsupportedDirectory
		}
		if !errors.Is(err, want) {
			t.Fatalf("guard: %v", err)
		}
	}
}

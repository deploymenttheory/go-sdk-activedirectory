package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDirectoryCapabilitiesAndADDSGuard(t *testing.T) {
	for _, tc := range []struct {
		name string
		oids []string
		want DirectoryType
	}{
		{"unknown", []string{"1.2.3.999"}, DirectoryUnknown},
		{"missing", nil, DirectoryUnknown},
		{"ds", []string{CapabilityActiveDirectory}, DirectoryADDS},
		{"lds", []string{CapabilityADLDS}, DirectoryADLDS},
		{"lds-and-generic", []string{CapabilityActiveDirectory, CapabilityADLDS, "1.2.3.999"}, DirectoryADLDS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := RootDSE{SupportedCapabilities: slices.Clone(tc.oids)}
			capabilities := root.Capabilities()
			if capabilities.Type != tc.want || !slices.Equal(capabilities.OIDs, tc.oids) {
				t.Fatalf("capabilities=%+v", capabilities)
			}
			err := capabilities.RequireADDS("domain operation")
			if tc.want == DirectoryADDS {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var prerequisite *DirectoryCapabilityError
				if !errors.Is(err, ErrUnsupportedDirectory) || !errors.As(err, &prerequisite) || prerequisite.Required != DirectoryADDS || prerequisite.Actual != tc.want || !strings.Contains(err.Error(), tc.want.String()) {
					t.Fatalf("imprecise guard error: %v", err)
				}
			}
			if len(capabilities.OIDs) != 0 {
				capabilities.OIDs[0] = "changed"
				if !slices.Equal(root.SupportedCapabilities, tc.oids) {
					t.Fatal("capability slice aliases RootDSE")
				}
			}
		})
	}
}

func TestClientGuardNeverUsesFailedCapabilityRead(t *testing.T) {
	denied := &LDAPError{Operation: "capabilities", Code: 50}
	for _, readErr := range []error{nil, denied} {
		client := newClient(Config{Timeout: time.Second}, testSession{
			base: func(_ context.Context, base string, properties []string) (map[string][][]byte, error) {
				if base != "" || !slices.Equal(properties, []string{"supportedCapabilities"}) {
					t.Fatal("unexpected capability read")
				}
				return map[string][][]byte{"supportedcapabilities": {[]byte(CapabilityActiveDirectory), []byte(CapabilityADLDS)}}, readErr
			},
			finish: func() error { return nil },
		})
		err := client.RequireADDS(context.Background(), "domain operation")
		_ = client.Close()
		want := readErr
		if want == nil {
			want = ErrUnsupportedDirectory
		}
		if !errors.Is(err, want) {
			t.Fatalf("guard: %v", err)
		}
	}
}

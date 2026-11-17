//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"errors"
	"fmt"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_directory_settings "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/directory_settings"
)

// Read observations are injected; the public workflows write through actual
// WinLDAP to a loopback LDAP peer. No AD service or directory is contacted.
func TestNativeDirectorySettingsAndModeWireOwnership(t *testing.T) {
	for _, operation := range []string{"domain settings", "forest settings", "domain mode", "forest mode"} {
		for _, code := range []byte{0, 50, 10} {
			t.Run(fmt.Sprintf("%s-code%d", operation, code), func(t *testing.T) {
				f := InternalNewSettingsFixture()
				dn := InternalOperationTestDomain
				attribute, values := "msDS-LogonTimeSyncInterval", [][]byte{[]byte("0")}
				if operation == "forest settings" {
					dn, attribute, values = InternalSettingsPartitions, "uPNSuffixes", [][]byte{
						[]byte("example.test"),
						[]byte("例子.test"),
					}
				}
				if operation == "domain mode" || operation == "forest mode" {
					attribute, values = "msDS-Behavior-Version", [][]byte{[]byte("7")}
				}
				if operation == "forest mode" {
					dn = InternalSettingsPartitions
				}
				guid, err := admodel.GUIDFromBytes(f.InternalObjects[dn]["objectguid"][0])
				if err != nil {
					t.Fatal(err)
				}
				var encodedValues [][]byte
				for _, value := range values {
					encodedValues = append(encodedValues, InternalSearchBER(4, value))
				}
				attributeWire := InternalSearchBER(
					0x30,
					InternalSearchBER(4, []byte(attribute)),
					InternalSearchBER(0x31, encodedValues...),
				)
				body := append(
					InternalSearchBER(4, []byte(admodel.InternalObjectGUIDTarget(guid))),
					InternalSearchBER(
						0x30,
						InternalSearchBER(0x30, []byte{10, 1, 2}, attributeWire),
					)...)
				wire := InternalNewWriteWireFixture(t, 0x66, 0x67, body, nil, code)
				var counts InternalSearchNativeCounts
				native := InternalSearchWireClient(
					t,
					&InternalSearchWireFixture{InternalListener: wire.InternalListener},
					InternalCountedSearchAPI(&counts),
				)
				f.InternalWrite = func(ctx context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					return adengine.InternalClientSession(native).(*adengine.InternalLdapSession).InternalLdapWrite(
						ctx,
						request,
					)
				}
				client := f.InternalClient(t)
				var result admodel.ObjectMutationResult
				switch operation {
				case "domain settings":
					days := uint32(0)
					result, err = adservice_directory_settings.New(client).
						UpdateDomain(context.Background(), admodel.UpdateDomainRequest{Identity: InternalSettingsIdentity(false), LastLogonReplicationIntervalDays: &days})
				case "forest settings":
					suffixes := []string{"example.test", "例子.test"}
					result, err = adservice_directory_settings.New(client).
						UpdateForest(context.Background(), admodel.UpdateForestRequest{Identity: InternalSettingsIdentity(true), UPNSuffixes: &suffixes})
				default:
					var transition admodel.FunctionalLevelTransitionResult
					transition, err = InternalRunFunctionalMode(
						context.Background(),
						client,
						operation == "forest mode",
						7,
						false,
					)
					result = transition.Mutation
				}
				if code == 0 {
					if err != nil || result.State != admodel.ObjectWriteAccepted ||
						!result.Verified {
						t.Fatal(result, err)
					}
				} else {
					var rejection *admodel.LDAPError
					if result.State != admodel.ObjectWriteRejected || !errors.As(err, &rejection) ||
						rejection.Code != uint32(code) ||
						rejection.Diagnostic != "private wire diagnostic" {
						t.Fatal(result, err)
					}
					if code == 50 && !errors.Is(err, admodel.ErrObjectWritePermission) {
						t.Fatal(err)
					}
				}
				if len(f.InternalWrites) != 1 {
					t.Fatal("write replayed", f.InternalWrites)
				}
				if err := native.Close(); err != nil {
					t.Fatal(err)
				}
				if counts != (InternalSearchNativeCounts{}) {
					t.Fatalf("native owners retained: %+v", counts)
				}
			})
		}
	}
}

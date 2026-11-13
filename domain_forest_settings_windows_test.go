//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// Read observations are injected; the public workflows write through actual
// WinLDAP to a loopback LDAP peer. No AD service or directory is contacted.
func TestNativeDirectorySettingsAndModeWireOwnership(t *testing.T) {
	for _, operation := range []string{"domain settings", "forest settings", "domain mode", "forest mode"} {
		for _, code := range []byte{0, 50, 10} {
			t.Run(fmt.Sprintf("%s-code%d", operation, code), func(t *testing.T) {
				f := newSettingsFixture()
				dn := operationTestDomain
				attribute, values := "msDS-LogonTimeSyncInterval", [][]byte{[]byte("0")}
				if operation == "forest settings" {
					dn, attribute, values = settingsPartitions, "uPNSuffixes", [][]byte{[]byte("example.test"), []byte("例子.test")}
				}
				if operation == "domain mode" || operation == "forest mode" {
					attribute, values = "msDS-Behavior-Version", [][]byte{[]byte("7")}
				}
				if operation == "forest mode" {
					dn = settingsPartitions
				}
				guid, err := GUIDFromBytes(f.objects[dn]["objectguid"][0])
				if err != nil {
					t.Fatal(err)
				}
				var encodedValues [][]byte
				for _, value := range values {
					encodedValues = append(encodedValues, searchBER(4, value))
				}
				attributeWire := searchBER(0x30, searchBER(4, []byte(attribute)), searchBER(0x31, encodedValues...))
				body := append(searchBER(4, []byte(objectGUIDTarget(guid))), searchBER(0x30, searchBER(0x30, []byte{10, 1, 2}, attributeWire))...)
				wire := newWriteWireFixture(t, 0x66, 0x67, body, nil, code)
				var counts searchNativeCounts
				native := searchWireClient(t, &searchWireFixture{listener: wire.listener}, countedSearchAPI(&counts))
				f.write = func(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
					return native.session.(*ldapSession).ldapWrite(ctx, request)
				}
				client := f.client(t)
				var result ObjectMutationResult
				switch operation {
				case "domain settings":
					days := uint32(0)
					result, err = client.UpdateDomain(context.Background(), UpdateDomainRequest{Identity: settingsIdentity(false), LastLogonReplicationIntervalDays: &days})
				case "forest settings":
					suffixes := []string{"example.test", "例子.test"}
					result, err = client.UpdateForest(context.Background(), UpdateForestRequest{Identity: settingsIdentity(true), UPNSuffixes: &suffixes})
				default:
					var transition FunctionalLevelTransitionResult
					transition, err = runFunctionalMode(context.Background(), client, operation == "forest mode", 7, false)
					result = transition.Mutation
				}
				if code == 0 {
					if err != nil || result.State != ObjectWriteAccepted || !result.Verified {
						t.Fatal(result, err)
					}
				} else {
					var rejection *LDAPError
					if result.State != ObjectWriteRejected || !errors.As(err, &rejection) || rejection.Code != uint32(code) || rejection.Diagnostic != "private wire diagnostic" {
						t.Fatal(result, err)
					}
					if code == 50 && !errors.Is(err, ErrObjectWritePermission) {
						t.Fatal(err)
					}
				}
				if len(f.writes) != 1 {
					t.Fatal("write replayed", f.writes)
				}
				if err := native.Close(); err != nil {
					t.Fatal(err)
				}
				if counts != (searchNativeCounts{}) {
					t.Fatalf("native owners retained: %+v", counts)
				}
			})
		}
	}
}

//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authentication/identity"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/rpc"
)

// Native handle/options/unbind and credential erasure are real. The synchronous
// bind and its returned diagnostic allocations are controlled at the API seam;
// this tests error/ownership ordering, not a live server's diagnostic contents.
func TestBindFailurePreservesDetailsBeforeUnbind(t *testing.T) {
	for _, auth := range []string{"simple", "current", "explicit"} {
		for _, transport := range []Transport{TransportLDAP, TransportLDAPS, TransportStartTLS} {
			if auth == "simple" && transport == TransportLDAP {
				continue
			}
			for _, failure := range []string{"details", "absent", "empty", "diagnostic-query", "diagnostic-query-nil", "extended-query", "high-surrogate", "low-surrogate", "unterminated", "maximum-length", "all-failures", "cancel-bind", "success", "success-cancel"} {
				t.Run(fmt.Sprintf("%s/%d/%s", auth, transport, failure), func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					api := systemLDAPAPI()
					unbind, wipe := api.unbind, api.zeroIdentity
					binds, wipes, closes, lookups, released := 0, 0, 0, 0, 0
					var allocation, passwordView []uint16
					const private = "synthetic-private-diagnostic-\U0001f511"
					const extended = syscall.Errno(1326)
					originalPassword := []byte("synthetic-private-password")
					credentials := &Credentials{
						Username: "CN=reader,CN=partition",
						Password: slices.Clone(originalPassword),
					}
					config := Config{
						Endpoint:    Endpoint{Host: "lds.ad.sdk.test", Port: 51301},
						Transport:   transport,
						Credentials: credentials,
						Timeout:     time.Second,
					}
					if auth == "simple" {
						config.Authentication = AuthenticationSimple
					}
					if auth == "current" {
						config.Credentials = nil
					}
					failedBind := !strings.HasPrefix(failure, "success")
					diagnosticQueryFails := failure == "diagnostic-query" ||
						failure == "diagnostic-query-nil" ||
						failure == "all-failures"
					extendedQueryFails := failure == "extended-query" || failure == "all-failures"
					api.connect = func(*ldap.LDAP, *ldap.LDAP_TIMEVAL) uint32 { return 0 }
					api.startTLS = func(*ldap.LDAP, *uint32, **ldap.LDAPMessage, **ldap.LDAPControlW, **ldap.LDAPControlW) uint32 {
						return 0
					}
					api.bind = func(_ *ldap.LDAP, _ *string, password foundation.PWSTR, _ uint32) uint32 {
						binds++
						if auth == "simple" {
							passwordView = unsafe.Slice(password, len(originalPassword)+1)
						} else if auth == "explicit" {
							identity := (*rpc.SEC_WINNT_AUTH_IDENTITY_W)(unsafe.Pointer(password))
							passwordView = unsafe.Slice(
								identity.Password,
								int(identity.PasswordLength)+1,
							)
						}
						if failure == "cancel-bind" || failure == "success-cancel" ||
							failure == "all-failures" {
							cancel()
						}
						if failedBind {
							return 49
						}
						return 0
					}
					api.zeroIdentity = func(pointer unsafe.Pointer) { wipes++; wipe(pointer) }
					api.getOption = func(_ *ldap.LDAP, option int32, out unsafe.Pointer) uint32 {
						switch uint32(option) {
						case ldap.LDAP_OPT_SSL:
							*(*uint32)(out) = 1
						case ldap.LDAP_OPT_SCH_FLAGS:
							*(*uint32)(out) = schannelFlags
						case ldap.LDAP_OPT_SSL_INFO:
							info := (*identity.SecPkgContext_ConnectionInfo)(out)
							info.DwProtocol, info.DwCipherStrength = identity.SP_PROT_TLS1_3_CLIENT, 256
						case ldap.LDAP_OPT_SERVER_ERROR, ldap.LDAP_OPT_SERVER_EXT_ERROR:
							lookups++
							if !failedBind || binds != 1 || closes != 0 {
								t.Error("server details queried outside the failed-bind lifetime")
							}
							for _, unit := range passwordView {
								if unit != 0 {
									t.Error("credential storage survived into diagnostic capture")
								}
							}
							if uint32(option) == ldap.LDAP_OPT_SERVER_EXT_ERROR {
								if failure != "absent" {
									*(*uint32)(out) = uint32(extended)
								}
								if extendedQueryFails {
									return 83
								}
								return 0
							}
							if failure != "absent" && failure != "diagnostic-query-nil" {
								allocation = credentialUTF16([]byte(private))
								switch failure {
								case "empty":
									allocation = []uint16{0}
								case "diagnostic-query", "all-failures":
									// Failed output must be freed without reading it.
									allocation = []uint16{0xd800}
								case "high-surrogate":
									allocation = []uint16{0xd800, 'x', 0}
								case "low-surrogate":
									allocation = []uint16{0xdc00, 0}
								case "unterminated":
									allocation = slices.Repeat([]uint16{'x'}, 4096)
								case "maximum-length":
									allocation = append(slices.Repeat([]uint16{'x'}, 4095), 0)
								}
								*(*foundation.PWSTR)(out) = &allocation[0]
							}
							if diagnosticQueryFails {
								return 82
							}
						default:
							t.Errorf("unexpected option %d", option)
						}
						return 0
					}
					api.memoryFree = func(pointer foundation.PWSTR) {
						if len(allocation) == 0 || pointer != &allocation[0] || released != 0 ||
							closes != 0 {
							t.Error("unowned, repeated, or post-unbind diagnostic release")
						}
						released++
						clear(allocation)
					}
					api.unbind = func(handle *ldap.LDAP) uint32 {
						closes++
						if failedBind && lookups != 2 || len(allocation) != 0 && released != 1 {
							t.Error("unbind preceded diagnostic capture/release")
						}
						status := unbind(handle)
						if failure == "all-failures" {
							return 80
						}
						return status
					}
					session, err := dialWithAPI(ctx, config, api)
					if session != nil {
						if closeErr := session.close(); closeErr != nil {
							t.Fatal(closeErr)
						}
					}
					if failedBind {
						var native *LDAPError
						if session != nil || !errors.As(err, &native) || native.Code != 49 ||
							native.Operation != "ldap_bind_sW" {
							t.Fatalf("original bind status was lost: %v", err)
						}
						wantDiagnostic := private
						if failure == "absent" || failure == "empty" || diagnosticQueryFails ||
							failure == "high-surrogate" ||
							failure == "low-surrogate" ||
							failure == "unterminated" {
							wantDiagnostic = ""
						}
						if failure == "maximum-length" {
							wantDiagnostic = strings.Repeat("x", 4095)
						}
						if native.Diagnostic != wantDiagnostic {
							t.Fatal(
								"diagnostic was missing, decoded despite lookup failure, or invalid after release",
							)
						}
						if errors.Is(
							err,
							extended,
						) != (!extendedQueryFails && failure != "absent") {
							t.Fatal("extended status was lost or read despite lookup failure")
						}
						if diagnosticQueryFails && !hasLDAPCode(err, 82) ||
							extendedQueryFails && !hasLDAPCode(err, 83) {
							t.Fatal("diagnostic lookup status was lost")
						}
						if (failure == "high-surrogate" || failure == "low-surrogate" || failure == "unterminated") &&
							!errors.Is(err, ErrInvalidResult) {
							t.Fatal("malformed native diagnostic was not identified")
						}
						if diagnosticQueryFails && errors.Is(err, ErrInvalidResult) {
							t.Fatal("failed lookup output was decoded")
						}
					} else if failure == "success" && (session == nil || err != nil) {
						t.Fatalf("successful bind failed: %v", err)
					}
					if failure == "all-failures" && !hasLDAPCode(err, 80) {
						t.Fatal("unbind status was lost")
					}
					if (failure == "cancel-bind" || failure == "success-cancel" || failure == "all-failures") &&
						!errors.Is(err, context.Canceled) {
						t.Fatal("bind cancellation was lost")
					}
					if errors.Is(err, ErrTLSNegotiation) ||
						err != nil &&
							(strings.Contains(err.Error(), private) || strings.Contains(err.Error(), string(originalPassword))) {
						t.Fatal(
							"authentication error was mislabeled as TLS or exposed private text",
						)
					}
					wantWipes := 1
					if auth == "current" {
						wantWipes = 0
					}
					if binds != 1 || closes != 1 || wipes != wantWipes ||
						!slices.Equal(credentials.Password, originalPassword) {
						t.Fatal("bind/wipe/unbind ownership or caller password changed")
					}
				})
			}
		}
	}
}

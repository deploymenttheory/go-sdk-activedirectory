//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authentication/identity"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/rpc"
)

func TestExplicitCredentialNativeLayoutAndWipe(t *testing.T) {
	for _, tc := range []struct {
		name, user, domain, password string
	}{
		{"ascii", "user", "ADSDK", "test-password"},
		{"unicode", "użytkownik", "DÖMAIN", "Pāss🔑"},
		{"upn-empty-password", "user@example.test", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			credential := Credentials{Username: tc.user, Domain: tc.domain, Password: []byte(tc.password)}
			api := systemLDAPAPI()
			if err := api.credentialAvailable(); err != nil {
				t.Fatal(err)
			}
			var buffers [][]uint16
			var observed *rpc.SEC_WINNT_AUTH_IDENTITY_W
			binds, wipes := 0, 0
			api.bind = func(_ *ldap.LDAP, dn *string, pointer foundation.PWSTR, method uint32) uint32 {
				binds++
				if dn != nil || pointer == nil || method != 0x486 {
					t.Fatal("explicit identity did not reach Negotiate")
				}
				observed = (*rpc.SEC_WINNT_AUTH_IDENTITY_W)(unsafe.Pointer(pointer))
				if observed.Flags != rpc.SEC_WINNT_AUTH_IDENTITY_UNICODE {
					t.Fatal("identity encoding flag is not Unicode")
				}
				for i, field := range []struct {
					pointer *uint16
					length  uint32
					want    string
				}{
					{observed.User, observed.UserLength, tc.user},
					{observed.Domain, observed.DomainLength, tc.domain},
					{observed.Password, observed.PasswordLength, tc.password},
				} {
					if i == 1 && tc.domain == "" {
						if field.pointer != nil || field.length != 0 {
							t.Fatal("omitted domain was not NULL with zero length")
						}
						continue
					}
					want := utf16.Encode([]rune(field.want))
					if field.pointer == nil || int(field.length) != len(want) {
						t.Fatal("native UTF-16 pointer or code-unit count is wrong")
					}
					buffer := unsafe.Slice(field.pointer, int(field.length)+1)
					if !slices.Equal(buffer[:field.length], want) || buffer[field.length] != 0 {
						t.Fatal("native credential contents or terminator is wrong")
					}
					buffers = append(buffers, buffer)
				}
				return 49 // Wiping is required on authentication failure too.
			}
			zero := api.zeroIdentity
			api.zeroIdentity = func(pointer unsafe.Pointer) {
				wipes++
				password := unsafe.Slice(observed.Password, observed.PasswordLength)
				zero(pointer) // Execute the real SSPI erasure API without network access.
				for _, value := range password {
					if value != 0 {
						t.Fatal("native SSPI wipe left password data")
					}
				}
			}
			if status := bindIdentity(api, nil, &credential, 0x486); status != 49 {
				t.Fatal("bind status was not preserved")
			}
			if binds != 1 || wipes != 1 || *observed != (rpc.SEC_WINNT_AUTH_IDENTITY_W{}) {
				t.Fatal("credential structure was not erased exactly once")
			}
			for _, buffer := range buffers {
				for _, value := range buffer {
					if value != 0 {
						t.Fatal("temporary credential buffer survived cleanup")
					}
				}
			}
			if !bytes.Equal(credential.Password, []byte(tc.password)) {
				t.Fatal("SDK modified the caller-owned password")
			}
		})
	}
}

func TestMissingCredentialWiperFailsBeforeAllocation(t *testing.T) {
	api := systemLDAPAPI()
	api.find = func(proc *win32.Proc) error {
		if proc == identity.Procs.SspiZeroAuthIdentity {
			return errors.New("injected missing credential erasure export")
		}
		return nil
	}
	api.init = func(string, uint32) *ldap.LDAP {
		t.Fatal("allocated LDAP session without credential cleanup capability")
		return nil
	}
	config := Config{Endpoint: Endpoint{Host: "dc.example.test", Port: 389}, Timeout: time.Second, Credentials: &Credentials{Username: "user"}}
	if session, err := dialWithAPI(context.Background(), config, api); session != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("missing credential export was not actionable: %v", err)
	}
}

func TestExplicitDialPreservesCleanupAndFailures(t *testing.T) {
	for _, failure := range []string{"none", "bind", "bind-and-close", "cancel-during-bind"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			api := systemLDAPAPI()
			init, unbind, set, zero := api.init, api.unbind, api.setOption, api.zeroIdentity
			allocations, frees, binds, wipes := 0, 0, 0, 0
			options := make(map[int32]uint32)
			api.init = func(host string, port uint32) *ldap.LDAP {
				handle := init(host, port)
				if handle != nil {
					allocations++
				}
				return handle
			}
			api.unbind = func(handle *ldap.LDAP) uint32 {
				if wipes != 1 {
					t.Error("session unbound before credential erasure")
				}
				frees++
				status := unbind(handle)
				if failure == "bind-and-close" {
					return 80
				}
				return status
			}
			api.setOption = func(handle *ldap.LDAP, option int32, value unsafe.Pointer) uint32 {
				options[option] = *(*uint32)(value)
				return set(handle, option, value)
			}
			api.connect = func(*ldap.LDAP, *ldap.LDAP_TIMEVAL) uint32 { return 0 }
			api.bind = func(_ *ldap.LDAP, dn *string, pointer foundation.PWSTR, method uint32) uint32 {
				binds++
				if pointer == nil || dn != nil || method != 0x486 {
					t.Fatal("explicit dial used the wrong authentication arguments")
				}
				if failure == "cancel-during-bind" {
					cancel()
				}
				if failure != "none" {
					return 49
				}
				return 0
			}
			api.zeroIdentity = func(pointer unsafe.Pointer) {
				wipes++
				zero(pointer)
			}
			config := Config{Endpoint: Endpoint{Host: "dc.example.test", Port: 389}, Timeout: time.Second, Credentials: &Credentials{Username: "user", Domain: "EXAMPLE", Password: []byte("private")}}
			session, err := dialWithAPI(ctx, config, api)
			if failure == "none" {
				if err != nil || session == nil {
					t.Fatalf("explicit dial failed: %v", err)
				}
				if err := session.close(); err != nil {
					t.Fatal(err)
				}
			} else if session != nil || !hasLDAPCode(err, 49) {
				t.Fatalf("lost explicit authentication failure: %v", err)
			}
			if failure == "bind-and-close" && !hasLDAPCode(err, 80) {
				t.Fatal("lost session cleanup failure")
			}
			if failure == "cancel-during-bind" && !errors.Is(err, context.Canceled) {
				t.Fatal("lost context cancellation during bind")
			}
			if allocations != 1 || frees != 1 || binds != 1 || wipes != 1 {
				t.Fatal("explicit dial leaked, repeated authentication, or skipped credential cleanup")
			}
			for _, option := range []uint32{ldap.LDAP_OPT_SIGN, ldap.LDAP_OPT_ENCRYPT} {
				if options[int32(option)] != 1 {
					t.Fatal("explicit dial omitted signing or sealing")
				}
			}
		})
	}
}

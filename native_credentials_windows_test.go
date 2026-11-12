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

//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authentication/identity"
)

func TestTLSGatesCredentialSubmissionAndOwnsSession(t *testing.T) {
	for _, transport := range []Transport{TransportLDAPS, TransportStartTLS} {
		for _, failure := range []string{"none", "export", "connect", "upgrade", "server", "policy", "manual", "name-bypass", "ssl-info", "old-protocol", "cancel", "bind", "bind-close"} {
			t.Run(fmt.Sprintf("%d/%s", transport, failure), func(t *testing.T) {
				if transport == TransportLDAPS && (failure == "upgrade" || failure == "server") {
					t.Skip("StartTLS-only failure")
				}
				api := systemLDAPAPI()
				find, init, sslInit, unbind, setOption, wipe := api.find, api.init, api.sslInit, api.unbind, api.setOption, api.zeroIdentity
				allocations, frees, binds, wipes := 0, 0, 0, 0
				connected, upgraded, inspected := false, false, false
				options := map[int32]uint32{}
				var passwordView []uint16
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				api.find = func(proc *win32.Proc) error {
					if failure == "export" && (proc == ldap.Procs.Ldap_sslinitW || proc == ldap.Procs.Ldap_start_tls_s) {
						return errors.New("missing TLS export")
					}
					return find(proc)
				}
				api.init = func(host string, port uint32) *ldap.LDAP {
					if transport != TransportStartTLS {
						t.Fatal("LDAPS used plaintext initializer")
					}
					handle := init(host, port)
					if handle != nil {
						allocations++
					}
					return handle
				}
				api.sslInit = func(host string, port uint32, secure int32) *ldap.LDAP {
					if transport != TransportLDAPS || secure != 1 || port != 51301 {
						t.Fatal("incorrect LDAPS initialization")
					}
					handle := sslInit(host, port, secure)
					if handle != nil {
						allocations++
					}
					return handle
				}
				api.unbind = func(handle *ldap.LDAP) uint32 {
					frees++
					status := unbind(handle)
					if failure == "bind-close" {
						return 80
					}
					return status
				}
				api.setOption = func(handle *ldap.LDAP, option int32, value unsafe.Pointer) uint32 {
					options[option] = *(*uint32)(value)
					return setOption(handle, option, value)
				}
				api.connect = func(*ldap.LDAP, *ldap.LDAP_TIMEVAL) uint32 {
					connected = true
					if binds != 0 || options[int32(ldap.LDAP_OPT_SCH_FLAGS)] != schannelFlags {
						t.Fatal("connect preceded validation policy or followed bind")
					}
					if failure == "connect" {
						return 81
					}
					return 0
				}
				api.startTLS = func(_ *ldap.LDAP, server *uint32, _ **ldap.LDAPMessage, _, _ **ldap.LDAPControlW) uint32 {
					if transport != TransportStartTLS || !connected || binds != 0 {
						t.Fatal("invalid StartTLS sequence")
					}
					upgraded = true
					if failure == "upgrade" {
						return 91
					}
					if failure == "server" {
						*server = 52
						return 80
					}
					return 0
				}
				api.getOption = func(_ *ldap.LDAP, option int32, value unsafe.Pointer) uint32 {
					switch uint32(option) {
					case ldap.LDAP_OPT_SERVER_EXT_ERROR:
						*(*uint32)(value) = 5
					case ldap.LDAP_OPT_SSL:
						*(*uint32)(value) = 1
					case ldap.LDAP_OPT_SCH_FLAGS:
						flags := schannelFlags
						if failure == "policy" {
							flags &^= uint32(identity.SCH_CRED_AUTO_CRED_VALIDATION)
						}
						if failure == "manual" {
							flags |= uint32(identity.SCH_CRED_MANUAL_CRED_VALIDATION)
						}
						if failure == "name-bypass" {
							flags |= uint32(identity.SCH_CRED_NO_SERVERNAME_CHECK)
						}
						*(*uint32)(value) = flags
					case ldap.LDAP_OPT_SSL_INFO:
						if !connected || (transport == TransportStartTLS && !upgraded) || binds != 0 {
							t.Fatal("TLS inspected outside pre-bind negotiated stage")
						}
						inspected = true
						if failure == "ssl-info" {
							return 92
						}
						info := (*identity.SecPkgContext_ConnectionInfo)(value)
						info.DwProtocol = identity.SP_PROT_TLS1_2_CLIENT
						info.DwCipherStrength = 128
						if failure == "old-protocol" {
							info.DwProtocol = identity.SP_PROT_TLS1_CLIENT
						}
						if failure == "cancel" {
							cancel()
						}
					default:
						t.Fatalf("unexpected option %d", option)
					}
					return 0
				}
				secret := []byte("synthetic-\u0101-\U0001f511-password")
				original := slices.Clone(secret)
				api.bind = func(_ *ldap.LDAP, dn *string, password foundation.PWSTR, method uint32) uint32 {
					binds++
					if !inspected || dn == nil || *dn != "CN=user,CN=application" || method != uint32(ldap.LDAP_AUTH_SIMPLE) || win32.UTF16ToString(password) != string(secret) {
						t.Fatal("SIMPLE credential representation or TLS ordering is incorrect")
					}
					passwordView = unsafe.Slice(password, int(utf16Units(secret))+1)
					if failure == "bind" || failure == "bind-close" {
						return 49
					}
					return 0
				}
				api.zeroIdentity = func(pointer unsafe.Pointer) { wipes++; wipe(pointer) }
				config := Config{Endpoint: Endpoint{Host: "lds.ad.sdk.test", Port: 51301}, Transport: transport, Authentication: AuthenticationSimple, Credentials: &Credentials{Username: "CN=user,CN=application", Password: secret}, Timeout: time.Second}
				session, err := dialWithAPI(ctx, config, api)
				if failure == "none" {
					if err != nil || session == nil {
						t.Fatalf("TLS dial failed: %v", err)
					}
					if err := session.close(); err != nil {
						t.Fatal(err)
					}
				} else {
					if err == nil || session != nil {
						t.Fatalf("failure returned session: %v", err)
					}
					if failure == "export" && (!errors.Is(err, ErrUnsupported) || allocations != 0) {
						t.Fatal("TLS export failure allocated a handle")
					}
					if failure == "connect" && (!hasLDAPCode(err, 81) || !errors.Is(err, syscall.Errno(5))) {
						t.Fatalf("lost TLS statuses: %v", err)
					}
					if failure == "server" && (!hasLDAPCode(err, 80) || !hasLDAPCode(err, 52)) {
						t.Fatalf("lost StartTLS server status: %v", err)
					}
					if failure == "cancel" && !errors.Is(err, context.Canceled) {
						t.Fatalf("lost cancellation: %v", err)
					}
					if failure == "bind-close" && (!hasLDAPCode(err, 49) || !hasLDAPCode(err, 80)) {
						t.Fatalf("lost bind/cleanup error: %v", err)
					}
				}
				wantBinds := 0
				if failure == "none" || failure == "bind" || failure == "bind-close" {
					wantBinds = 1
				}
				if binds != wantBinds || wipes != wantBinds || allocations != frees {
					t.Fatalf("bind/wipe/allocate/free = %d/%d/%d/%d", binds, wipes, allocations, frees)
				}
				if options[int32(ldap.LDAP_OPT_SIGN)] != 0 || options[int32(ldap.LDAP_OPT_ENCRYPT)] != 0 {
					t.Fatal("SASL sign/seal enabled on TLS session")
				}
				for _, value := range passwordView {
					if value != 0 {
						t.Fatal("native SIMPLE password storage was not erased")
					}
				}
				if !slices.Equal(secret, original) {
					t.Fatal("caller-owned password changed")
				}
			})
		}
	}
}

func TestInsecureSimpleDialFailsBeforeNativeExecution(t *testing.T) {
	api := systemLDAPAPI()
	api.find = func(*win32.Proc) error { t.Fatal("insecure SIMPLE reached native boundary"); return nil }
	config := Config{Endpoint: Endpoint{Host: "lds.ad.sdk.test"}, Authentication: AuthenticationSimple, Credentials: &Credentials{Username: "CN=user", Password: []byte("synthetic")}}
	if session, err := dialWithAPI(context.Background(), config, api); session != nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("insecure SIMPLE: %v", err)
	}
}

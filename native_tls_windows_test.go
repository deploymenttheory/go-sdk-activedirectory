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

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authentication/identity"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/rpc"
)

func TestTLSGatesCredentialSubmissionAndOwnsSession(t *testing.T) {
	for _, authMode := range []string{"simple", "current", "explicit"} {
		for _, transport := range []Transport{TransportLDAPS, TransportStartTLS} {
			for _, failure := range []string{"none", "tls13", "export", "callback", "configure", "connect", "upgrade", "server", "response-parse", "response-server", "response-free", "policy", "manual", "name-bypass", "default-creds", "flags-get", "ssl-get", "ssl-disabled", "ssl-info", "old-protocol", "weak-cipher", "cancel", "cancel-connect", "cancel-upgrade", "cancel-timeout", "bind", "bind-close"} {
				t.Run(fmt.Sprintf("%s/%d/%s", authMode, transport, failure), func(t *testing.T) {
					if transport == TransportLDAPS &&
						(failure == "upgrade" || failure == "server" || strings.HasPrefix(failure, "response-")) {
						t.Skip("StartTLS-only failure")
					}
					if transport == TransportStartTLS &&
						(failure == "ssl-get" || failure == "ssl-disabled") {
						t.Skip("direct LDAPS-only option gate")
					}
					api := systemLDAPAPI()
					find, init, sslInit, unbind, setOption, wipe := api.find, api.init, api.sslInit, api.unbind, api.setOption, api.zeroIdentity
					installCertificateCallback := api.setClientCertificate
					allocations, frees, binds, wipes := 0, 0, 0, 0
					responseFrees := 0
					response := new(ldap.LDAPMessage)
					connected, upgraded, inspected := false, false, false
					options := map[int32]uint32{}
					var passwordView []uint16
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					api.find = func(proc *win32.Proc) error {
						if failure == "export" &&
							(proc == ldap.Procs.Ldap_sslinitW || proc == ldap.Procs.Ldap_start_tls_s) {
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
						if failure == "configure" && uint32(option) == ldap.LDAP_OPT_SCH_FLAGS {
							return 53
						}
						if failure == "cancel-timeout" && inspected {
							cancel()
						}
						return setOption(handle, option, value)
					}
					api.setClientCertificate = func(handle *ldap.LDAP, callback ldap.QUERYCLIENTCERT) uint32 {
						if callback == 0 || callback != noTLSClientCertificate() || connected ||
							binds != 0 {
							t.Fatal(
								"client-certificate policy was installed after connecting or used an unstable callback",
							)
						}
						if failure == "callback" {
							return 53
						}
						return installCertificateCallback(handle, callback)
					}
					api.connect = func(*ldap.LDAP, *ldap.LDAP_TIMEVAL) uint32 {
						connected = true
						if failure == "cancel-connect" {
							cancel()
						}
						if binds != 0 || options[int32(ldap.LDAP_OPT_SCH_FLAGS)] != schannelFlags {
							t.Fatal("connect preceded validation policy or followed bind")
						}
						if failure == "connect" {
							return 81
						}
						return 0
					}
					api.startTLS = func(_ *ldap.LDAP, server *uint32, out **ldap.LDAPMessage, _, _ **ldap.LDAPControlW) uint32 {
						if transport != TransportStartTLS || !connected || binds != 0 {
							t.Fatal("invalid StartTLS sequence")
						}
						upgraded = true
						if strings.HasPrefix(failure, "response-") {
							*out = response
						}
						if failure == "cancel-upgrade" {
							cancel()
						}
						if failure == "upgrade" {
							return 91
						}
						if failure == "server" {
							*server = 52
							return 80
						}
						return 0
					}
					api.parseResult = func(_ *ldap.LDAP, got *ldap.LDAPMessage, code *uint32, _, _ *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, _ foundation.BOOLEAN) uint32 {
						if got != response {
							t.Fatal("unexpected TLS response")
						}
						if failure == "response-parse" {
							return 84
						}
						if failure == "response-server" {
							*code = 53
						}
						return 0
					}
					api.messageFree = func(got *ldap.LDAPMessage) uint32 {
						if got != response {
							t.Fatal("unexpected response free")
						}
						responseFrees++
						if failure == "response-free" {
							return 82
						}
						return 0
					}
					api.getOption = func(_ *ldap.LDAP, option int32, value unsafe.Pointer) uint32 {
						switch uint32(option) {
						case ldap.LDAP_OPT_SERVER_ERROR:
							*(*foundation.PWSTR)(value) = nil
						case ldap.LDAP_OPT_SERVER_EXT_ERROR:
							*(*uint32)(value) = 5
						case ldap.LDAP_OPT_SSL:
							if failure == "ssl-get" {
								return 92
							}
							if failure == "ssl-disabled" {
								return 0
							}
							*(*uint32)(value) = 1
						case ldap.LDAP_OPT_SCH_FLAGS:
							if failure == "flags-get" {
								return 92
							}
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
							if failure == "default-creds" {
								flags |= uint32(identity.SCH_CRED_USE_DEFAULT_CREDS)
							}
							*(*uint32)(value) = flags
						case ldap.LDAP_OPT_SSL_INFO:
							if !connected || (transport == TransportStartTLS && !upgraded) ||
								binds != 0 {
								t.Fatal("TLS inspected outside pre-bind negotiated stage")
							}
							inspected = true
							if failure == "ssl-info" {
								return 92
							}
							info := (*identity.SecPkgContext_ConnectionInfo)(value)
							info.DwProtocol = identity.SP_PROT_TLS1_2_CLIENT
							info.DwCipherStrength = 128
							if failure == "tls13" {
								info.DwProtocol = identity.SP_PROT_TLS1_3_CLIENT
							}
							if failure == "weak-cipher" {
								info.DwCipherStrength = 0
							}
							if failure == "cancel-upgrade" && transport == TransportLDAPS {
								cancel()
							}
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
						if !inspected {
							t.Fatal("bind preceded TLS inspection")
						}
						if authMode == "simple" {
							if dn == nil || *dn != "CN=user,CN=application" ||
								method != uint32(ldap.LDAP_AUTH_SIMPLE) ||
								win32.UTF16ToString(password) != string(secret) {
								t.Fatal("SIMPLE credential representation is incorrect")
							}
							passwordView = unsafe.Slice(password, int(utf16Units(secret))+1)
						} else {
							if dn != nil || method != 0x486 {
								t.Fatal("incorrect Negotiate bind")
							}
							if authMode == "current" {
								if password != nil {
									t.Fatal("current identity received explicit credentials")
								}
							} else {
								auth := (*rpc.SEC_WINNT_AUTH_IDENTITY_W)(unsafe.Pointer(password))
								if auth == nil ||
									win32.UTF16ToString(auth.User) != "CN=user,CN=application" ||
									win32.UTF16ToString(auth.Password) != string(secret) {
									t.Fatal("incorrect explicit Negotiate identity")
								}
								passwordView = unsafe.Slice(
									auth.Password,
									int(auth.PasswordLength)+1,
								)
							}
						}
						if failure == "bind" || failure == "bind-close" {
							return 49
						}
						return 0
					}
					api.zeroIdentity = func(pointer unsafe.Pointer) { wipes++; wipe(pointer) }
					config := Config{
						Endpoint:       Endpoint{Host: "lds.ad.sdk.test", Port: 51301},
						Transport:      transport,
						Authentication: AuthenticationSimple,
						Credentials: &Credentials{
							Username: "CN=user,CN=application",
							Password: secret,
						},
						Timeout: time.Second,
					}
					if authMode != "simple" {
						config.Authentication = AuthenticationNegotiate
					}
					if authMode == "current" {
						config.Credentials = nil
					}
					session, err := dialWithAPI(ctx, config, api)
					if failure == "none" || failure == "tls13" {
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
						if failure == "export" &&
							(!errors.Is(err, ErrUnsupported) || allocations != 0) {
							t.Fatal("TLS export failure allocated a handle")
						}
						if failure == "connect" &&
							(!hasLDAPCode(err, 81) || !errors.Is(err, syscall.Errno(5))) {
							t.Fatalf("lost TLS statuses: %v", err)
						}
						if failure == "server" && (!hasLDAPCode(err, 80) || !hasLDAPCode(err, 52)) {
							t.Fatalf("lost StartTLS server status: %v", err)
						}
						if strings.HasPrefix(failure, "cancel") &&
							!errors.Is(err, context.Canceled) {
							t.Fatalf("lost cancellation: %v", err)
						}
						if failure == "bind-close" &&
							(!hasLDAPCode(err, 49) || !hasLDAPCode(err, 80)) {
							t.Fatalf("lost bind/cleanup error: %v", err)
						}
					}
					wantBinds := 0
					if failure == "none" || failure == "tls13" || failure == "bind" ||
						failure == "bind-close" {
						wantBinds = 1
					}
					wantWipes := wantBinds
					if authMode == "current" {
						wantWipes = 0
					}
					if binds != wantBinds || wipes != wantWipes || allocations != frees {
						t.Fatalf(
							"bind/wipe/allocate/free = %d/%d/%d/%d",
							binds,
							wipes,
							allocations,
							frees,
						)
					}
					wantResponseFrees := 0
					if strings.HasPrefix(failure, "response-") {
						wantResponseFrees = 1
					}
					if responseFrees != wantResponseFrees {
						t.Fatalf("TLS response frees=%d", responseFrees)
					}
					if options[int32(ldap.LDAP_OPT_SIGN)] != 0 ||
						options[int32(ldap.LDAP_OPT_ENCRYPT)] != 0 {
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
}

// Real WinLDAP allocation/options/unbind, with no connection or certificate
// handshake. This records option storage behavior, not TLS trust validation.
func TestNativeSchannelPolicyRoundTripBeforeConnect(t *testing.T) {
	api := systemLDAPAPI()
	if err := api.available(); err != nil {
		t.Fatal(err)
	}
	for _, transport := range []Transport{TransportLDAPS, TransportStartTLS} {
		t.Run(fmt.Sprint(transport), func(t *testing.T) {
			if err := api.tlsAvailable(transport); err != nil {
				t.Fatal(err)
			}
			var handle *ldap.LDAP
			if transport == TransportLDAPS {
				handle = api.sslInit("127.0.0.1", 51301, 1)
			} else {
				handle = api.init("127.0.0.1", 51300)
			}
			if handle == nil {
				t.Fatalf("native allocation: LDAP %d", api.lastError())
			}
			session := &ldapSession{api: api, handle: handle}
			defer func() {
				if err := session.close(); err != nil {
					t.Error(err)
				}
			}()
			if err := session.configureTLS(); err != nil {
				t.Fatal(err)
			}
			var flags uint32
			if status := api.getOption(
				handle,
				int32(ldap.LDAP_OPT_SCH_FLAGS),
				unsafe.Pointer(&flags),
			); status != 0 {
				t.Fatalf("Schannel option read: LDAP %d", status)
			}
			if flags != schannelFlags {
				t.Fatalf("Schannel flags %#x, want %#x", flags, schannelFlags)
			}
			t.Logf("pre-connect Schannel policy %#x", flags)
		})
	}
}

func TestInsecureSimpleDialFailsBeforeNativeExecution(t *testing.T) {
	api := systemLDAPAPI()
	api.find = func(*win32.Proc) error { t.Fatal("insecure SIMPLE reached native boundary"); return nil }
	config := Config{
		Endpoint:       Endpoint{Host: "lds.ad.sdk.test"},
		Authentication: AuthenticationSimple,
		Credentials:    &Credentials{Username: "CN=user", Password: []byte("synthetic")},
	}
	if session, err := dialWithAPI(
		context.Background(),
		config,
		api,
	); session != nil ||
		!errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("insecure SIMPLE: %v", err)
	}
}

func TestStartTLSResponsePreservesStatusesAndReleasesOwners(t *testing.T) {
	for _, failure := range []string{"none", "server", "parse", "free", "combined", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			message := new(ldap.LDAPMessage)
			owners := map[foundation.PWSTR]string{}
			freed, parsed := 0, 0
			session := &ldapSession{handle: new(ldap.LDAP), timeout: time.Second, api: ldapAPI{
				setOption: func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 },
				startTLS: func(_ *ldap.LDAP, server *uint32, out **ldap.LDAPMessage, serverControls, clientControls **ldap.LDAPControlW) uint32 {
					if serverControls != nil || clientControls != nil {
						t.Fatal("unexpected TLS controls")
					}
					*out = message
					if failure == "cancel" {
						cancel()
					}
					if failure == "combined" {
						*server = 52
						return 80
					}
					return 0
				},
				parseResult: func(_ *ldap.LDAP, got *ldap.LDAPMessage, code *uint32, matched, diagnostic *foundation.PWSTR, referrals ***uint16, controls ***ldap.LDAPControlW, freeIt foundation.BOOLEAN) uint32 {
					parsed++
					if got != message || freeIt != 0 || referrals != nil || controls != nil {
						t.Fatal("invalid parse ownership")
					}
					*matched = win32.UTF16Ptr("CN=private-partition")
					*diagnostic = win32.UTF16Ptr("private diagnostic")
					owners[*matched] = "CN=private-partition"
					owners[*diagnostic] = "private diagnostic"
					if failure == "server" || failure == "combined" {
						*code = 53
					}
					if failure == "parse" || failure == "combined" {
						return 84
					}
					return 0
				},
				memoryFree: func(p foundation.PWSTR) {
					value, ok := owners[p]
					if !ok {
						t.Fatal("unowned or double string free")
					}
					clear(unsafe.Slice(p, len(value)+1))
					delete(owners, p)
				},
				messageFree: func(got *ldap.LDAPMessage) uint32 {
					if got != message || parsed != 1 || len(owners) != 0 {
						t.Fatal("invalid message release order")
					}
					freed++
					if failure == "free" || failure == "combined" {
						return 82
					}
					return 0
				},
				getOption: func(_ *ldap.LDAP, option int32, out unsafe.Pointer) uint32 {
					if uint32(option) != ldap.LDAP_OPT_SERVER_EXT_ERROR {
						t.Fatal("unexpected error query")
					}
					*(*uint32)(out) = 5
					return 0
				},
			}}
			err := session.startTLS(ctx)
			if freed != 1 || parsed != 1 || len(owners) != 0 {
				t.Fatalf("parse/free/owners=%d/%d/%d", parsed, freed, len(owners))
			}
			if failure == "none" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, ErrTLSNegotiation) || !errors.Is(err, syscall.Errno(5)) {
				t.Fatalf("lost TLS/native status: %v", err)
			}
			if failure == "combined" {
				for _, code := range []uint32{80, 52, 53, 84, 82} {
					if !hasLDAPCode(err, code) {
						t.Fatalf("lost status %d: %v", code, err)
					}
				}
			}
			if failure == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
			if failure == "server" {
				var native *LDAPError
				if !errors.As(err, &native) || native.Diagnostic != "private diagnostic" ||
					native.MatchedDN != "CN=private-partition" {
					t.Fatalf("lost native details: %v", err)
				}
				if strings.Contains(err.Error(), "private") {
					t.Fatal("error string disclosed diagnostic")
				}
			}
			if failure == "parse" {
				var native *LDAPError
				if !errors.As(err, &native) || native.Code != 84 ||
					native.Diagnostic != "" || native.MatchedDN != "" {
					t.Fatalf("failed parse exposed unvalidated strings: %v", err)
				}
			}
		})
	}
}

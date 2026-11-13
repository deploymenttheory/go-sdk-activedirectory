//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authentication/identity"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/credentials"
)

func TestNativeMoveSecurityRequiresEstablishedDelegatedKerberos(t *testing.T) {
	for _, mode := range []string{"valid", "no-context", "invalid-context", "get-failed", "missing-export", "flags-failed", "package-failed", "in-progress", "nil-package", "NTLM", "no-delegate", "no-mutual", "free-failed", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			queried, freed := 0, 0
			session := &ldapSession{handle: new(ldap.LDAP), api: ldapAPI{getOption: func(_ *ldap.LDAP, option int32, out unsafe.Pointer) uint32 {
				if option != int32(ldap.LDAP_OPT_SECURITY_CONTEXT) {
					t.Fatal(option)
				}
				if mode == "get-failed" {
					return 82
				}
				if mode == "no-context" {
					return 0
				}
				*(*credentials.SecHandle)(out) = credentials.SecHandle{DwLower: 12, DwUpper: 34}
				if mode == "invalid-context" {
					*(*credentials.SecHandle)(out) = credentials.SecHandle{DwLower: ^uintptr(0), DwUpper: ^uintptr(0)}
				}
				return 0
			}}}
			pkg := &identity.SecPkgInfoW{Name: win32.UTF16Ptr("Kerberos")}
			api := moveSecurityAPI{find: func(*win32.Proc) error {
				if mode == "missing-export" {
					return ErrUnsupported
				}
				return nil
			}, query: func(handle *credentials.SecHandle, attribute identity.SECPKG_ATTR, out unsafe.Pointer) error {
				queried++
				if handle.DwLower != 12 || handle.DwUpper != 34 {
					t.Fatal("borrowed handle changed")
				}
				switch attribute {
				case identity.SECPKG_ATTR_FLAGS:
					if mode == "flags-failed" {
						return ErrUnsupported
					}
					flags := identity.ISC_RET_DELEGATE | identity.ISC_RET_MUTUAL_AUTH
					if mode == "no-delegate" {
						flags &^= identity.ISC_RET_DELEGATE
					}
					if mode == "no-mutual" {
						flags &^= identity.ISC_RET_MUTUAL_AUTH
					}
					(*identity.SecPkgContext_Flags)(out).Flags = flags
				case identity.SECPKG_ATTR_NEGOTIATION_INFO:
					if mode == "package-failed" {
						return ErrUnsupported
					}
					info := (*identity.SecPkgContext_NegotiationInfoW)(out)
					if mode != "nil-package" {
						info.PackageInfo = pkg
					}
					if mode == "in-progress" {
						info.NegotiationState = identity.SECPKG_NEGOTIATION_IN_PROGRESS
					}
					if mode == "NTLM" {
						pkg.Name = win32.UTF16Ptr("NTLM")
					}
					if mode == "canceled" {
						cancel()
					}
				default:
					t.Fatal("unexpected security query", attribute)
				}
				return nil
			}, free: func(p unsafe.Pointer) error {
				freed++
				if p != unsafe.Pointer(pkg) {
					t.Fatal("wrong SSPI allocation")
				}
				if mode == "free-failed" {
					return ErrInvalidResult
				}
				return nil
			}}
			result, err := session.moveSecurityWith(ctx, api)
			if mode == "valid" {
				if err != nil || !result.Complete || !result.Delegated || result.Package != "Kerberos" {
					t.Fatal(result, err)
				}
			} else if err == nil || result.Complete {
				t.Fatal(result, err)
			}
			wantFree := 1
			switch mode {
			case "no-context", "invalid-context", "get-failed", "missing-export", "flags-failed", "package-failed", "nil-package":
				wantFree = 0
			}
			if freed != wantFree || queried > 2 || session.handle == nil {
				t.Fatal("security ownership", queried, freed)
			}
		})
	}
}

func TestNativeDialDelegationOptInPreservesSecurityFlags(t *testing.T) {
	for _, mode := range []string{"disabled", "enabled", "read-failed", "set-failed"} {
		t.Run(mode, func(t *testing.T) {
			api := systemLDAPAPI()
			get, set, unbind := api.getOption, api.setOption, api.unbind
			reads, sets, binds, closes := 0, 0, 0, 0
			const original = uint32(identity.ISC_REQ_CONFIDENTIALITY | identity.ISC_REQ_INTEGRITY | identity.ISC_REQ_REPLAY_DETECT)
			api.getOption = func(h *ldap.LDAP, option int32, out unsafe.Pointer) uint32 {
				if option == int32(ldap.LDAP_OPT_SSPI_FLAGS) {
					reads++
					if mode == "read-failed" {
						return 82
					}
					*(*uint32)(out) = original
					return 0
				}
				return get(h, option, out)
			}
			api.setOption = func(h *ldap.LDAP, option int32, in unsafe.Pointer) uint32 {
				if option == int32(ldap.LDAP_OPT_SSPI_FLAGS) {
					sets++
					if *(*uint32)(in) != original|uint32(identity.ISC_REQ_DELEGATE|identity.ISC_REQ_MUTUAL_AUTH) {
						t.Fatal("existing flags lost")
					}
					if binds != 0 {
						t.Fatal("delegation set after bind")
					}
					if mode == "set-failed" {
						return 82
					}
				}
				return set(h, option, in)
			}
			api.connect = func(*ldap.LDAP, *ldap.LDAP_TIMEVAL) uint32 { return 0 }
			api.bind = func(_ *ldap.LDAP, _ *string, _ foundation.PWSTR, method uint32) uint32 {
				binds++
				if method != 0x486 {
					t.Fatal(method)
				}
				return 0
			}
			api.unbind = func(h *ldap.LDAP) uint32 { closes++; return unbind(h) }
			session, err := dialWithAPI(context.Background(), Config{Endpoint: Endpoint{Host: "src.example"}, AllowDelegation: mode != "disabled", Timeout: time.Second}, api)
			if mode == "enabled" || mode == "disabled" {
				if err != nil {
					t.Fatal(err)
				}
				if err := session.close(); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || session != nil || binds != 0 {
				t.Fatal("failed delegation permitted bind", err, binds)
			}
			if mode == "disabled" && (reads != 0 || sets != 0) {
				t.Fatal("implicit delegation")
			}
			if mode == "enabled" && (reads != 1 || sets != 1 || binds != 1) {
				t.Fatal(reads, sets, binds)
			}
			if closes != 1 {
				t.Fatal("handle leak", closes)
			}
		})
	}
}

func TestNativeMoveRejectsMalformedNewParent(t *testing.T) {
	for _, request := range []ldapWriteRequest{{operation: ldapWriteRename, dn: "CN=a", newRDN: "CN=a", newParent: "OU=bad\x00"}, {operation: ldapWriteRename, dn: "CN=a", newRDN: "CN=a", newParent: string([]byte{255})}, {operation: ldapWriteDelete, dn: "CN=a", newParent: "OU=b"}} {
		if err := validateLDAPWrite(request); !errors.Is(err, ErrInvalidResult) {
			t.Fatal(err)
		}
	}
}

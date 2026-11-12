//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

func TestNativePartitionBaseReadPreservesDNAndNativeFailure(t *testing.T) {
	for _, failure := range []string{"missing", "denied", "referral", "submit", "canceled"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			const base = `cn=App\2cOne,dc=example,dc=test`
			searches, frees, closes, abandons := 0, 0, 0, 0
			message := new(ldap.LDAPMessage)
			code := uint32(32)
			if failure == "denied" {
				code = 50
			}
			if failure == "referral" {
				code = 10
			}
			session := &ldapSession{handle: new(ldap.LDAP), timeout: time.Second, api: ldapAPI{
				setOption: func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 },
				search: func(_ *ldap.LDAP, dn *string, scope uint32, filter string, attrs **uint16, attrOnly uint32, serverControls, clientControls **ldap.LDAPControlW, seconds, limit uint32, id *uint32) uint32 {
					searches++
					if dn == nil || *dn != base || scope != ldap.LDAP_SCOPE_BASE || filter != "(objectClass=*)" || attrOnly != 0 || serverControls != nil || clientControls != nil || seconds != 1 || limit != 0 {
						t.Fatal("altered base read request")
					}
					pointers := unsafe.Slice(attrs, 3)
					if pointers[2] != nil || !slices.Equal([]string{win32.UTF16ToString(pointers[0]), win32.UTF16ToString(pointers[1])}, []string{"distinguishedName", "instanceType"}) {
						t.Fatal("incorrect attribute array")
					}
					*id = 7
					if failure == "submit" {
						return 81
					}
					if failure == "canceled" {
						cancel()
					}
					return 0
				},
				result: func(_ *ldap.LDAP, id, all uint32, _ *ldap.LDAP_TIMEVAL, out **ldap.LDAPMessage) uint32 {
					if id != 7 || all != ldap.LDAP_MSG_ALL {
						t.Fatal("incorrect pending request")
					}
					*out = message
					return uint32(ldap.LDAP_RES_SEARCH_RESULT)
				},
				parseResult: func(_ *ldap.LDAP, _ *ldap.LDAPMessage, out *uint32, _, _ *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, _ foundation.BOOLEAN) uint32 {
					*out = code
					return 0
				},
				countEntries: func(*ldap.LDAP, *ldap.LDAPMessage) uint32 { return 0 },
				messageFree: func(got *ldap.LDAPMessage) uint32 {
					if got != message {
						t.Fatal("wrong message")
					}
					frees++
					return 0
				},
				unbind: func(*ldap.LDAP) uint32 { closes++; return 80 },
				abandon: func(_ *ldap.LDAP, id uint32) uint32 {
					if id != 7 {
						t.Fatal("wrong abandoned request")
					}
					abandons++
					return 0
				},
			}}
			_, err := session.baseObject(ctx, base, []string{"distinguishedName", "instanceType"})
			if searches != 1 {
				t.Fatal("request repeated")
			}
			switch failure {
			case "submit":
				if !hasLDAPCode(err, 81) || !hasLDAPCode(err, 80) || closes != 1 || session.handle != nil || frees != 0 {
					t.Fatalf("uncertain submission: %v", err)
				}
			case "canceled":
				if !errors.Is(err, context.Canceled) || abandons != 1 || frees != 0 || closes != 0 {
					t.Fatalf("canceled request: %v", err)
				}
			default:
				if !hasLDAPCode(err, code) || errors.Is(err, ErrInvalidResult) || frees != 1 || closes != 0 {
					t.Fatalf("native read failure: %v", err)
				}
			}
		})
	}
}

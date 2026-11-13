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
)

type passwordPolicyNativeSession struct {
	directorySession
	native   *ldapSession
	dispatch ldapModifyFunc
}

func (s passwordPolicyNativeSession) ldapModify(ctx context.Context, dn string, mods []ldapModification) ldapWriteAttempt {
	return s.native.ldapModifyWith(ctx, dn, mods, s.dispatch)
}

func TestPasswordPolicySharedNativeWriteBoundary(t *testing.T) {
	for _, test := range []struct {
		name  string
		code  uint32
		state PasswordPolicyWriteState
		want  error
	}{
		{"accepted", 0, PasswordPolicyWriteAccepted, nil},
		{"permission", 50, PasswordPolicyWriteRejected, ErrPasswordPolicyPermission},
		{"lost-response", 81, PasswordPolicyWriteUncertain, ErrPasswordPolicyUncertain},
	} {
		t.Run(test.name, func(t *testing.T) {
			objects := passwordPolicyFixture()
			client := passwordPolicyClient(objects, nil)
			var submits, frees, closes int
			native := &ldapSession{handle: new(ldap.LDAP), timeout: time.Second}
			native.api.find = func(*win32.Proc) error { return nil }
			native.api.setOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 }
			native.api.result = func(_ *ldap.LDAP, id, _ uint32, _ *ldap.LDAP_TIMEVAL, message **ldap.LDAPMessage) uint32 {
				if id != 7 {
					t.Fatal("wrong response ID")
				}
				*message = new(ldap.LDAPMessage)
				return uint32(ldap.LDAP_RES_MODIFY)
			}
			native.api.parseResult = func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, _, _ *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, _ foundation.BOOLEAN) uint32 {
				*code = test.code
				return 0
			}
			native.api.messageFree = func(*ldap.LDAPMessage) uint32 { frees++; return 0 }
			native.api.unbind = func(*ldap.LDAP) uint32 { closes++; return 0 }
			client.session = passwordPolicyNativeSession{directorySession: client.session, native: native, dispatch: func(_ *ldap.LDAP, dn string, modifications **ldap.LDAPModW, server, local **ldap.LDAPControlW, id *uint32) uint32 {
				submits++
				if dn != operationTestDomain || server != nil || local != nil {
					t.Fatal("wrong target or unexpected controls")
				}
				// Complexity off must delete the old complete bitmask, then add
				// the new bitmask with every unrelated flag still present.
				mods := unsafe.Slice(modifications, 3)
				if mods[2] != nil {
					t.Fatal("unexpected modifications")
				}
				for i, expected := range []string{"63", "62"} {
					name, err := copyLDAPText(mods[i].Mod_type)
					wantOp := uint32(1-i) | ldap.LDAP_MOD_BVALUES
					if err != nil || name != "pwdProperties" || mods[i].Mod_op != wantOp {
						t.Fatal("wrong policy mutation")
					}
					values := unsafe.Slice(*(***ldap.LDAP_BERVAL)(unsafe.Pointer(&mods[i].Mod_vals)), 2)
					if values[0] == nil || values[1] != nil {
						t.Fatal("malformed values")
					}
					value := unsafe.Slice((*byte)(unsafe.Pointer(values[0].Bv_val)), int(values[0].Bv_len))
					if string(value) != expected {
						t.Fatalf("value=%s want=%s", value, expected)
					}
				}
				if test.code == 0 {
					objects[operationTestDomain]["pwdproperties"] = [][]byte{[]byte("62")}
				}
				*id = 7
				return 0
			}}
			result, err := client.UpdateDefaultDomainPasswordPolicy(context.Background(), DomainPasswordPolicyUpdate{ComplexityEnabled: policyPointer(false)})
			if result.WriteState != test.state || !errors.Is(err, test.want) || submits != 1 || frees != 1 || result.Verified != (test.code == 0) {
				t.Fatalf("result=%+v err=%v submits=%d frees=%d", result, err, submits, frees)
			}
			if test.code == 81 && (closes != 1 || native.handle != nil || errors.Is(err, ErrOperationMasterUncertain)) {
				t.Fatal("incorrect uncertainty ownership or feature error", err)
			}
			if test.code != 81 && closes != 0 {
				t.Fatal("retired an acknowledged response")
			}
		})
	}
}

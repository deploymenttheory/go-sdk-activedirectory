//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

func TestSyncObjectNativePolicyControlAndOwnership(t *testing.T) {
	for _, submissionFailure := range []bool{false, true} {
		submits, frees, closes := 0, 0, 0
		s := &ldapSession{handle: new(ldap.LDAP), timeout: time.Second}
		s.api.setOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 }
		s.api.unbind = func(*ldap.LDAP) uint32 { closes++; return 0 }
		s.api.search = func(_ *ldap.LDAP, dn *string, scope uint32, filter string, attrs **uint16, only uint32, server, client **ldap.LDAPControlW, seconds, limit uint32, id *uint32) uint32 {
			runtime.GC()
			submits++
			if *dn != syncTestTarget || scope != ldap.LDAP_SCOPE_BASE || filter != "(objectClass=*)" || only != 0 || client != nil || limit != 0 {
				t.Fatal("altered policy read")
			}
			if win32.UTF16ToString(*attrs) != "msDS-IsUserCachableAtRodc" || unsafe.Slice(attrs, 2)[1] != nil {
				t.Fatal("wrong policy projection")
			}
			controls := unsafe.Slice(server, 2)
			if controls[0] == nil || controls[1] != nil || controls[0].Ldctl_iscritical != 1 || win32.UTF16ToString(controls[0].Ldctl_oid) != objectSyncDNInputOID {
				t.Fatal("missing critical DN input")
			}
			value := controls[0].Ldctl_value
			var decoded struct{ InputDN []byte }
			rest, err := asn1.Unmarshal(unsafe.Slice((*byte)(unsafe.Pointer(value.Bv_val)), int(value.Bv_len)), &decoded)
			if err != nil || len(rest) != 0 || string(decoded.InputDN) != syncTestObject {
				t.Fatalf("bad UTF-8 DN BER: %q %v", decoded.InputDN, err)
			}
			*id = 7
			if submissionFailure {
				return 81
			}
			return 0
		}
		s.api.result = func(_ *ldap.LDAP, id, all uint32, _ *ldap.LDAP_TIMEVAL, m **ldap.LDAPMessage) uint32 {
			*m = new(ldap.LDAPMessage)
			return uint32(ldap.LDAP_RES_SEARCH_RESULT)
		}
		s.api.parseResult = func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, _, _ *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, _ foundation.BOOLEAN) uint32 {
			*code = 50
			return 0
		}
		s.api.messageFree = func(*ldap.LDAPMessage) uint32 { frees++; return 0 }
		s.api.countEntries = func(*ldap.LDAP, *ldap.LDAPMessage) uint32 { return 0 }
		_, err := s.objectSyncPasswordPolicy(context.Background(), syncTestTarget, syncTestObject)
		var native *LDAPError
		if !errors.As(err, &native) || submits != 1 {
			t.Fatalf("%v submits=%d", err, submits)
		}
		if submissionFailure {
			if native.Code != 81 || closes != 1 || frees != 0 {
				t.Fatalf("%v closes=%d frees=%d", err, closes, frees)
			}
		} else if native.Code != 50 || frees != 1 || closes != 0 {
			t.Fatalf("%v closes=%d frees=%d", err, closes, frees)
		}
	}
}

func TestSyncObjectNativeModifyPreservesOneRootRequest(t *testing.T) {
	f := newSyncFixture(t)
	want := []byte(syncGUIDDN(f.src[syncTestSource]["objectguid"][0]) + ":" + syncGUIDDN(f.src[syncTestObject]["objectguid"][0]) + ":SECRETS_ONLY")
	s := &ldapSession{handle: new(ldap.LDAP), timeout: time.Second}
	s.api.find = func(*win32.Proc) error { return nil }
	s.api.setOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 }
	s.api.result = func(_ *ldap.LDAP, _, _ uint32, _ *ldap.LDAP_TIMEVAL, m **ldap.LDAPMessage) uint32 {
		*m = new(ldap.LDAPMessage)
		return uint32(ldap.LDAP_RES_MODIFY)
	}
	s.api.parseResult = func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, _, _ *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, _ foundation.BOOLEAN) uint32 {
		*code = 0
		return 0
	}
	frees := 0
	s.api.messageFree = func(*ldap.LDAPMessage) uint32 { frees++; return 0 }
	attempt := s.ldapModifyWith(context.Background(), "", []ldapModification{{2, "replicateSingleObject", want}}, func(_ *ldap.LDAP, dn string, mods **ldap.LDAPModW, server, client **ldap.LDAPControlW, id *uint32) uint32 {
		runtime.GC()
		pointers := unsafe.Slice(mods, 2)
		if dn != "" || server != nil || client != nil || pointers[1] != nil || pointers[0].Mod_op != 2|ldap.LDAP_MOD_BVALUES || win32.UTF16ToString(pointers[0].Mod_type) != "replicateSingleObject" {
			t.Fatal("wrong modify request")
		}
		values := unsafe.Slice(*(***ldap.LDAP_BERVAL)(unsafe.Pointer(&pointers[0].Mod_vals)), 2)
		if values[1] != nil || !bytes.Equal(unsafe.Slice((*byte)(unsafe.Pointer(values[0].Bv_val)), int(values[0].Bv_len)), want) {
			t.Fatal("altered replicateSingleObject value")
		}
		*id = 9
		return 0
	})
	if attempt.Err != nil || attempt.State != ldapWriteAccepted || frees != 1 {
		t.Fatalf("%+v frees=%d", attempt, frees)
	}
}

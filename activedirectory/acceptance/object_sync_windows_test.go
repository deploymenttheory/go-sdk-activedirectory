//go:build windows && (amd64 || arm64)

package acceptance

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
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestSyncObjectNativePolicyControlAndOwnership(t *testing.T) {
	for _, submissionFailure := range []bool{false, true} {
		submits, frees, closes := 0, 0, 0
		s := &adengine.InternalLdapSession{
			InternalHandle:  new(ldap.LDAP),
			InternalTimeout: time.Second,
		}
		s.InternalApi.InternalSetOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 }
		s.InternalApi.InternalUnbind = func(*ldap.LDAP) uint32 { closes++; return 0 }
		s.InternalApi.InternalSearch = func(_ *ldap.LDAP, dn *string, scope uint32, filter string, attrs **uint16, only uint32, server, client **ldap.LDAPControlW, seconds, limit uint32, id *uint32) uint32 {
			runtime.GC()
			submits++
			if *dn != InternalSyncTestTarget || scope != ldap.LDAP_SCOPE_BASE ||
				filter != "(objectClass=*)" ||
				only != 0 ||
				client != nil ||
				limit != 0 {
				t.Fatal("altered policy read")
			}
			if win32.UTF16ToString(*attrs) != "msDS-IsUserCachableAtRodc" ||
				unsafe.Slice(attrs, 2)[1] != nil {
				t.Fatal("wrong policy projection")
			}
			controls := unsafe.Slice(server, 2)
			if controls[0] == nil || controls[1] != nil || controls[0].Ldctl_iscritical != 1 ||
				win32.UTF16ToString(controls[0].Ldctl_oid) != admodel.InternalObjectSyncDNInputOID {
				t.Fatal("missing critical DN input")
			}
			value := controls[0].Ldctl_value
			var decoded struct{ InputDN []byte }
			rest, err := asn1.Unmarshal(
				unsafe.Slice((*byte)(unsafe.Pointer(value.Bv_val)), int(value.Bv_len)),
				&decoded,
			)
			if err != nil || len(rest) != 0 || string(decoded.InputDN) != InternalSyncTestObject {
				t.Fatalf("bad UTF-8 DN BER: %q %v", decoded.InputDN, err)
			}
			*id = 7
			if submissionFailure {
				return 81
			}
			return 0
		}
		s.InternalApi.InternalResult = func(_ *ldap.LDAP, id, all uint32, _ *ldap.LDAP_TIMEVAL, m **ldap.LDAPMessage) uint32 {
			*m = new(ldap.LDAPMessage)
			return uint32(ldap.LDAP_RES_SEARCH_RESULT)
		}
		s.InternalApi.InternalParseResult = func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, _, _ *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, _ foundation.BOOLEAN) uint32 {
			*code = 50
			return 0
		}
		s.InternalApi.InternalMessageFree = func(*ldap.LDAPMessage) uint32 { frees++; return 0 }
		s.InternalApi.InternalCountEntries = func(*ldap.LDAP, *ldap.LDAPMessage) uint32 { return 0 }
		_, err := s.InternalObjectSyncPasswordPolicy(
			context.Background(),
			InternalSyncTestTarget,
			InternalSyncTestObject,
		)
		var native *admodel.LDAPError
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
	f := InternalNewSyncFixture(t)
	want := []byte(
		admodel.InternalSyncGUIDDN(
			f.InternalSrc[InternalSyncTestSource]["objectguid"][0],
		) + ":" + admodel.InternalSyncGUIDDN(
			f.InternalSrc[InternalSyncTestObject]["objectguid"][0],
		) + ":SECRETS_ONLY",
	)
	s := &adengine.InternalLdapSession{InternalHandle: new(ldap.LDAP), InternalTimeout: time.Second}
	s.InternalApi.InternalFind = func(*win32.Proc) error { return nil }
	s.InternalApi.InternalSetOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 }
	s.InternalApi.InternalResult = func(_ *ldap.LDAP, _, _ uint32, _ *ldap.LDAP_TIMEVAL, m **ldap.LDAPMessage) uint32 {
		*m = new(ldap.LDAPMessage)
		return uint32(ldap.LDAP_RES_MODIFY)
	}
	s.InternalApi.InternalParseResult = func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, _, _ *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, _ foundation.BOOLEAN) uint32 {
		*code = 0
		return 0
	}
	frees := 0
	s.InternalApi.InternalMessageFree = func(*ldap.LDAPMessage) uint32 { frees++; return 0 }
	attempt := s.InternalLdapModifyWith(
		context.Background(),
		"",
		[]admodel.InternalLdapModification{
			{InternalOperation: 2, InternalAttribute: "replicateSingleObject", InternalValue: want},
		},
		func(_ *ldap.LDAP, dn string, mods **ldap.LDAPModW, server, client **ldap.LDAPControlW, id *uint32) uint32 {
			runtime.GC()
			pointers := unsafe.Slice(mods, 2)
			if dn != "" || server != nil || client != nil || pointers[1] != nil ||
				pointers[0].Mod_op != 2|ldap.LDAP_MOD_BVALUES ||
				win32.UTF16ToString(pointers[0].Mod_type) != "replicateSingleObject" {
				t.Fatal("wrong modify request")
			}
			values := unsafe.Slice(*(***ldap.LDAP_BERVAL)(unsafe.Pointer(&pointers[0].Mod_vals)), 2)
			if values[1] != nil ||
				!bytes.Equal(
					unsafe.Slice((*byte)(unsafe.Pointer(values[0].Bv_val)), int(values[0].Bv_len)),
					want,
				) {
				t.Fatal("altered replicateSingleObject value")
			}
			*id = 9
			return 0
		},
	)
	if attempt.Err != nil || attempt.State != admodel.InternalLdapWriteAccepted || frees != 1 {
		t.Fatalf("%+v frees=%d", attempt, frees)
	}
}

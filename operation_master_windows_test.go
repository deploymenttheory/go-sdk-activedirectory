//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"bytes"
	"context"
	"errors"
	"math"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

func TestOperationMasterNativeRequestOwnsBinaryAndUTF8Values(t *testing.T) {
	_, _, sid := operationMasterFixture()
	for _, test := range []struct {
		dn   string
		mods []operationMasterModification
	}{
		{"", []operationMasterModification{{0, "becomePdc", sid}}},
		{operationTestRID, []operationMasterModification{{1, "fSMORoleOwner", []byte(operationTestOld)}, {0, "fSMORoleOwner", []byte("CN=NTDS Settings,CN=Dŵr," + operationTestConfig)}, {1, "rIDAvailablePool", []byte("4611686014132422708")}, {0, "rIDAvailablePool", []byte("4611686014132452708")}}},
	} {
		session := &ldapSession{handle: new(ldap.LDAP), timeout: time.Second}
		session.api.find = func(*win32.Proc) error { return nil }
		session.api.setOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 }
		session.api.result = func(_ *ldap.LDAP, id, all uint32, _ *ldap.LDAP_TIMEVAL, result **ldap.LDAPMessage) uint32 {
			if id != 42 || all != ldap.LDAP_MSG_ALL {
				t.Fatal("wrong write result request")
			}
			*result = new(ldap.LDAPMessage)
			return uint32(ldap.LDAP_RES_MODIFY)
		}
		session.api.parseResult = func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, _, _ *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, free foundation.BOOLEAN) uint32 {
			if free != 0 {
				t.Fatal("parser must not free the owned message")
			}
			*code = 0
			return 0
		}
		frees := 0
		session.api.messageFree = func(*ldap.LDAPMessage) uint32 { frees++; return 0 }
		attempt := session.operationMasterModifyWith(context.Background(), test.dn, test.mods, func(_ *ldap.LDAP, dn string, mods **ldap.LDAPModW, server, client **ldap.LDAPControlW, id *uint32) uint32 {
			runtime.GC()
			if dn != test.dn || server != nil || client != nil {
				t.Fatal("changed destination or added permissive controls")
			}
			pointers := unsafe.Slice(mods, len(test.mods)+1)
			if pointers[len(test.mods)] != nil {
				t.Fatal("missing modification terminator")
			}
			for i, want := range test.mods {
				mod := pointers[i]
				name, err := copyLDAPText(mod.Mod_type)
				if err != nil || name != want.attribute || mod.Mod_op != want.operation|ldap.LDAP_MOD_BVALUES {
					t.Fatalf("invalid mod %d: %+v, %v", i, mod, err)
				}
				values := unsafe.Slice(*(***ldap.LDAP_BERVAL)(unsafe.Pointer(&mod.Mod_vals)), 2)
				if values[0] == nil || values[1] != nil {
					t.Fatal("invalid berval list")
				}
				value := unsafe.Slice((*byte)(unsafe.Pointer(values[0].Bv_val)), int(values[0].Bv_len))
				if !bytes.Equal(value, want.value) {
					t.Fatalf("value=%x want=%x", value, want.value)
				}
			}
			*id = 42
			return 0
		})
		if attempt.State != OperationMasterWriteAccepted || attempt.Err != nil || frees != 1 {
			t.Fatalf("attempt=%+v frees=%d", attempt, frees)
		}
	}
}

func TestOperationMasterNativeFailureOwnershipAndUncertainty(t *testing.T) {
	for _, test := range []struct {
		name                                        string
		state                                       OperationMasterWriteState
		writes, abandons, closes, messages, strings int
	}{
		{"missing-export", OperationMasterWriteNotAttempted, 0, 0, 0, 0, 0},
		{"canceled-before", OperationMasterWriteNotAttempted, 0, 0, 0, 0, 0},
		{"option", OperationMasterWriteNotAttempted, 0, 0, 0, 0, 0},
		{"submit", OperationMasterWriteUncertain, 1, 0, 1, 0, 0},
		{"cancel-after", OperationMasterWriteUncertain, 1, 1, 1, 0, 0},
		{"abandon-fails", OperationMasterWriteUncertain, 1, 1, 1, 0, 0},
		{"result", OperationMasterWriteUncertain, 1, 1, 1, 1, 0},
		{"wrong-kind", OperationMasterWriteUncertain, 1, 1, 1, 1, 0},
		{"parse", OperationMasterWriteUncertain, 1, 0, 1, 1, 2},
		{"transport", OperationMasterWriteUncertain, 1, 0, 1, 1, 2},
		{"no-result", OperationMasterWriteUncertain, 1, 0, 1, 1, 2},
		{"referral-limit", OperationMasterWriteUncertain, 1, 0, 1, 1, 2},
		{"permission", OperationMasterWriteRejected, 1, 0, 0, 1, 2},
		{"unavailable", OperationMasterWriteRejected, 1, 0, 0, 1, 2},
		{"cancel-after-response", OperationMasterWriteAccepted, 1, 0, 0, 1, 2},
		{"free-fails", OperationMasterWriteAccepted, 1, 0, 1, 1, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var writes, abandons, closes, messages, stringsFreed int
			var order []string
			session := &ldapSession{handle: new(ldap.LDAP), timeout: time.Second}
			session.api.find = func(*win32.Proc) error {
				if test.name == "missing-export" {
					return ErrUnsupported
				}
				return nil
			}
			session.api.setOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 {
				if test.name == "option" {
					return 89
				}
				return 0
			}
			session.api.unbind = func(*ldap.LDAP) uint32 { closes++; order = append(order, "close"); return 0 }
			session.api.abandon = func(_ *ldap.LDAP, id uint32) uint32 {
				if id != 99 {
					t.Fatal("abandoned unknown ID")
				}
				abandons++
				order = append(order, "abandon")
				if test.name == "abandon-fails" {
					return 80
				}
				return 0
			}
			session.api.getOption = func(_ *ldap.LDAP, _ int32, value unsafe.Pointer) uint32 { *(*uint32)(value) = 81; return 0 }
			session.api.result = func(_ *ldap.LDAP, _ uint32, _ uint32, _ *ldap.LDAP_TIMEVAL, message **ldap.LDAPMessage) uint32 {
				*message = new(ldap.LDAPMessage)
				if test.name == "result" {
					return math.MaxUint32
				}
				if test.name == "wrong-kind" {
					return uint32(ldap.LDAP_RES_SEARCH_RESULT)
				}
				return uint32(ldap.LDAP_RES_MODIFY)
			}
			session.api.parseResult = func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, matched, diagnostic *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, _ foundation.BOOLEAN) uint32 {
				*matched, *diagnostic = win32.UTF16Ptr(operationTestDomain), win32.UTF16Ptr("000020AF: private server diagnostic")
				switch test.name {
				case "parse":
					return 84
				case "permission":
					*code = 50
				case "unavailable":
					*code = 52
				case "transport":
					*code = 81
				case "no-result":
					*code = 94
				case "referral-limit":
					*code = 97
				case "cancel-after-response":
					cancel()
				}
				return 0
			}
			session.api.memoryFree = func(foundation.PWSTR) { stringsFreed++ }
			session.api.messageFree = func(*ldap.LDAPMessage) uint32 {
				messages++
				order = append(order, "message")
				if test.name == "free-fails" {
					return 80
				}
				return 0
			}
			if test.name == "canceled-before" {
				cancel()
			}
			attempt := session.operationMasterModifyWith(ctx, "", []operationMasterModification{{0, "becomeSchemaMaster", []byte("1")}}, func(_ *ldap.LDAP, _ string, _ **ldap.LDAPModW, _, _ **ldap.LDAPControlW, id *uint32) uint32 {
				writes++
				if test.name == "submit" {
					return 81
				}
				*id = 99
				if test.name == "cancel-after" || test.name == "abandon-fails" {
					cancel()
				}
				return 0
			})
			if attempt.State != test.state || attempt.Err == nil || writes != test.writes || abandons != test.abandons || closes != test.closes || messages != test.messages || stringsFreed != test.strings {
				t.Fatalf("attempt=%+v writes=%d abandons=%d closes=%d messages=%d strings=%d", attempt, writes, abandons, closes, messages, stringsFreed)
			}
			if test.state == OperationMasterWriteUncertain && !errors.Is(attempt.Err, ErrOperationMasterUncertain) {
				t.Fatal("missing uncertainty sentinel")
			}
			if test.name == "result" || test.name == "wrong-kind" {
				if len(order) != 3 || order[0] != "message" || order[1] != "abandon" || order[2] != "close" {
					t.Fatal(order)
				}
			}
			if test.name == "permission" || test.name == "unavailable" {
				var native *LDAPError
				if !errors.As(attempt.Err, &native) || native.Diagnostic == "" || native.MatchedDN != operationTestDomain {
					t.Fatal("lost server error details")
				}
			}
			if test.closes != 0 {
				second := session.operationMasterModifyWith(context.Background(), "", nil, nil)
				if second.State != OperationMasterWriteNotAttempted || !errors.Is(second.Err, ErrClosed) {
					t.Fatalf("retired session reusable: %+v", second)
				}
				if err := session.close(); err != nil {
					t.Fatal(err)
				}
				if closes != 1 {
					t.Fatal("double unbind")
				}
			}
		})
	}
}

//go:build windows && (amd64 || arm64)

package acceptance

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
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestOperationMasterNativeRequestOwnsBinaryAndUTF8Values(t *testing.T) {
	_, _, sid := InternalOperationMasterFixture()
	for _, test := range []struct {
		InternalDn   string
		InternalMods []admodel.InternalOperationMasterModification
	}{
		{"", []admodel.InternalOperationMasterModification{{InternalOperation: 0, InternalAttribute: "becomePdc", InternalValue: sid}}},
		{InternalOperationTestRID, []admodel.InternalOperationMasterModification{{InternalOperation: 1, InternalAttribute: "fSMORoleOwner", InternalValue: []byte(InternalOperationTestOld)}, {InternalOperation: 0, InternalAttribute: "fSMORoleOwner", InternalValue: []byte("CN=NTDS Settings,CN=Dŵr," + InternalOperationTestConfig)}, {InternalOperation: 1, InternalAttribute: "rIDAvailablePool", InternalValue: []byte("4611686014132422708")}, {InternalOperation: 0, InternalAttribute: "rIDAvailablePool", InternalValue: []byte("4611686014132452708")}}},
	} {
		session := &adengine.InternalLdapSession{
			InternalHandle:  new(ldap.LDAP),
			InternalTimeout: time.Second,
		}
		session.InternalApi.InternalFind = func(*win32.Proc) error { return nil }
		session.InternalApi.InternalSetOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 }
		session.InternalApi.InternalResult = func(_ *ldap.LDAP, id, all uint32, _ *ldap.LDAP_TIMEVAL, result **ldap.LDAPMessage) uint32 {
			if id != 42 || all != ldap.LDAP_MSG_ALL {
				t.Fatal("wrong write result request")
			}
			*result = new(ldap.LDAPMessage)
			return uint32(ldap.LDAP_RES_MODIFY)
		}
		session.InternalApi.InternalParseResult = func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, _, _ *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, free foundation.BOOLEAN) uint32 {
			if free != 0 {
				t.Fatal("parser must not free the owned message")
			}
			*code = 0
			return 0
		}
		frees := 0
		session.InternalApi.InternalMessageFree = func(*ldap.LDAPMessage) uint32 { frees++; return 0 }
		attempt := session.InternalOperationMasterModifyWith(
			context.Background(),
			test.InternalDn,
			test.InternalMods,
			func(_ *ldap.LDAP, dn string, mods **ldap.LDAPModW, server, client **ldap.LDAPControlW, id *uint32) uint32 {
				runtime.GC()
				if dn != test.InternalDn || server != nil || client != nil {
					t.Fatal("changed destination or added permissive controls")
				}
				pointers := unsafe.Slice(mods, len(test.InternalMods)+1)
				if pointers[len(test.InternalMods)] != nil {
					t.Fatal("missing modification terminator")
				}
				for i, want := range test.InternalMods {
					mod := pointers[i]
					name, err := adengine.InternalCopyLDAPText(mod.Mod_type)
					if err != nil || name != want.InternalAttribute ||
						mod.Mod_op != want.InternalOperation|ldap.LDAP_MOD_BVALUES {
						t.Fatalf("invalid mod %d: %+v, %v", i, mod, err)
					}
					values := unsafe.Slice(*(***ldap.LDAP_BERVAL)(unsafe.Pointer(&mod.Mod_vals)), 2)
					if values[0] == nil || values[1] != nil {
						t.Fatal("invalid berval list")
					}
					value := unsafe.Slice(
						(*byte)(unsafe.Pointer(values[0].Bv_val)),
						int(values[0].Bv_len),
					)
					if !bytes.Equal(value, want.InternalValue) {
						t.Fatalf("value=%x want=%x", value, want.InternalValue)
					}
				}
				*id = 42
				return 0
			},
		)
		if attempt.State != admodel.OperationMasterWriteAccepted || attempt.Err != nil ||
			frees != 1 {
			t.Fatalf("attempt=%+v frees=%d", attempt, frees)
		}
	}
}

func TestOperationMasterNativeFailureOwnershipAndUncertainty(t *testing.T) {
	for _, test := range []struct {
		InternalName                                                                        string
		InternalState                                                                       admodel.OperationMasterWriteState
		InternalWrites, InternalAbandons, InternalCloses, InternalMessages, InternalStrings int
	}{
		{"missing-export", admodel.OperationMasterWriteNotAttempted, 0, 0, 0, 0, 0},
		{"canceled-before", admodel.OperationMasterWriteNotAttempted, 0, 0, 0, 0, 0},
		{"option", admodel.OperationMasterWriteNotAttempted, 0, 0, 0, 0, 0},
		{"submit", admodel.OperationMasterWriteUncertain, 1, 0, 1, 0, 0},
		{"cancel-after", admodel.OperationMasterWriteUncertain, 1, 1, 1, 0, 0},
		{"abandon-fails", admodel.OperationMasterWriteUncertain, 1, 1, 1, 0, 0},
		{"result", admodel.OperationMasterWriteUncertain, 1, 1, 1, 1, 0},
		{"wrong-kind", admodel.OperationMasterWriteUncertain, 1, 1, 1, 1, 0},
		{"parse", admodel.OperationMasterWriteUncertain, 1, 0, 1, 1, 2},
		{"transport", admodel.OperationMasterWriteUncertain, 1, 0, 1, 1, 2},
		{"no-result", admodel.OperationMasterWriteUncertain, 1, 0, 1, 1, 2},
		{"referral-limit", admodel.OperationMasterWriteUncertain, 1, 0, 1, 1, 2},
		{"permission", admodel.OperationMasterWriteRejected, 1, 0, 0, 1, 2},
		{"unavailable", admodel.OperationMasterWriteRejected, 1, 0, 0, 1, 2},
		{"cancel-after-response", admodel.OperationMasterWriteAccepted, 1, 0, 0, 1, 2},
		{"free-fails", admodel.OperationMasterWriteAccepted, 1, 0, 1, 1, 2},
	} {
		t.Run(test.InternalName, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var writes, abandons, closes, messages, stringsFreed int
			var order []string
			session := &adengine.InternalLdapSession{
				InternalHandle:  new(ldap.LDAP),
				InternalTimeout: time.Second,
			}
			session.InternalApi.InternalFind = func(*win32.Proc) error {
				if test.InternalName == "missing-export" {
					return admodel.ErrUnsupported
				}
				return nil
			}
			session.InternalApi.InternalSetOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 {
				if test.InternalName == "option" {
					return 89
				}
				return 0
			}
			session.InternalApi.InternalUnbind = func(*ldap.LDAP) uint32 { closes++; order = append(order, "close"); return 0 }
			session.InternalApi.InternalAbandon = func(_ *ldap.LDAP, id uint32) uint32 {
				if id != 99 {
					t.Fatal("abandoned unknown ID")
				}
				abandons++
				order = append(order, "abandon")
				if test.InternalName == "abandon-fails" {
					return 80
				}
				return 0
			}
			session.InternalApi.InternalGetOption = func(_ *ldap.LDAP, _ int32, value unsafe.Pointer) uint32 { *(*uint32)(value) = 81; return 0 }
			session.InternalApi.InternalResult = func(_ *ldap.LDAP, _ uint32, _ uint32, _ *ldap.LDAP_TIMEVAL, message **ldap.LDAPMessage) uint32 {
				*message = new(ldap.LDAPMessage)
				if test.InternalName == "result" {
					return math.MaxUint32
				}
				if test.InternalName == "wrong-kind" {
					return uint32(ldap.LDAP_RES_SEARCH_RESULT)
				}
				return uint32(ldap.LDAP_RES_MODIFY)
			}
			session.InternalApi.InternalParseResult = func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, matched, diagnostic *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, _ foundation.BOOLEAN) uint32 {
				*matched, *diagnostic = win32.UTF16Ptr(
					InternalOperationTestDomain,
				), win32.UTF16Ptr(
					"000020AF: private server diagnostic",
				)
				switch test.InternalName {
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
			session.InternalApi.InternalMemoryFree = func(foundation.PWSTR) { stringsFreed++ }
			session.InternalApi.InternalMessageFree = func(*ldap.LDAPMessage) uint32 {
				messages++
				order = append(order, "message")
				if test.InternalName == "free-fails" {
					return 80
				}
				return 0
			}
			if test.InternalName == "canceled-before" {
				cancel()
			}
			attempt := session.InternalOperationMasterModifyWith(
				ctx,
				"",
				[]admodel.InternalOperationMasterModification{
					{
						InternalOperation: 0,
						InternalAttribute: "becomeSchemaMaster",
						InternalValue:     []byte("1"),
					},
				},
				func(_ *ldap.LDAP, _ string, _ **ldap.LDAPModW, _, _ **ldap.LDAPControlW, id *uint32) uint32 {
					writes++
					if test.InternalName == "submit" {
						return 81
					}
					*id = 99
					if test.InternalName == "cancel-after" || test.InternalName == "abandon-fails" {
						cancel()
					}
					return 0
				},
			)
			if attempt.State != test.InternalState || attempt.Err == nil ||
				writes != test.InternalWrites ||
				abandons != test.InternalAbandons ||
				closes != test.InternalCloses ||
				messages != test.InternalMessages ||
				stringsFreed != test.InternalStrings {
				t.Fatalf(
					"attempt=%+v writes=%d abandons=%d closes=%d messages=%d strings=%d",
					attempt,
					writes,
					abandons,
					closes,
					messages,
					stringsFreed,
				)
			}
			if test.InternalState == admodel.OperationMasterWriteUncertain &&
				!errors.Is(attempt.Err, admodel.ErrOperationMasterUncertain) {
				t.Fatal("missing uncertainty sentinel")
			}
			if test.InternalName == "result" || test.InternalName == "wrong-kind" {
				if len(order) != 3 || order[0] != "message" || order[1] != "abandon" ||
					order[2] != "close" {
					t.Fatal(order)
				}
			}
			if test.InternalName == "permission" || test.InternalName == "unavailable" {
				var native *admodel.LDAPError
				if !errors.As(attempt.Err, &native) || native.Diagnostic == "" ||
					native.MatchedDN != InternalOperationTestDomain {
					t.Fatal("lost server error details")
				}
			}
			if test.InternalCloses != 0 {
				second := session.InternalOperationMasterModifyWith(
					context.Background(),
					"",
					nil,
					nil,
				)
				if second.State != admodel.OperationMasterWriteNotAttempted ||
					!errors.Is(second.Err, admodel.ErrClosed) {
					t.Fatalf("retired session reusable: %+v", second)
				}
				if err := session.InternalClose(); err != nil {
					t.Fatal(err)
				}
				if closes != 1 {
					t.Fatal("double unbind")
				}
			}
		})
	}
}

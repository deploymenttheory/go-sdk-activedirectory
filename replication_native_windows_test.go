//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"testing"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	nativead "github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/activedirectory"
)

func TestReplicationNativeFailureCopyAndOwnership(t *testing.T) {
	for _, kind := range []nativead.DS_REPL_INFO_TYPE{nativead.DS_REPL_INFO_KCC_DSA_CONNECT_FAILURES, nativead.DS_REPL_INFO_KCC_DSA_LINK_FAILURES} {
		t.Run(string(rune('0'+kind)), func(t *testing.T) {
			name := []uint16{'C', 'N', '=', 'X', 0}
			owner := nativead.DS_REPL_KCC_DSA_FAILURESW{CNumEntries: 1}
			owner.RgDsaFailure[0] = nativead.DS_REPL_KCC_DSA_FAILUREW{PszDsaDN: &name[0], UuidDsaObjGuid: win32.GUID{Data1: 123}, FtimeFirstFailure: foundation.FILETIME{DwHighDateTime: 1, DwLowDateTime: 42}, CNumFailures: 3, DwLastResult: 1722}
			freed := 0
			api := replicationAPI{
				getInfo: func(h foundation.HANDLE, k nativead.DS_REPL_INFO_TYPE, object *string, source *win32.GUID, attr, value *string, flags, enumeration uint32, out *unsafe.Pointer) uint32 {
					if h != 17 || k != kind || object != nil || source != nil || attr != nil || value != nil || flags != 0 || enumeration != 0 {
						t.Fatal("unexpected native query")
					}
					*out = unsafe.Pointer(&owner)
					return 0
				},
				freeInfo: func(k nativead.DS_REPL_INFO_TYPE, p unsafe.Pointer) {
					if k != kind || p != unsafe.Pointer(&owner) {
						t.Fatal("wrong free")
					}
					freed++
					clear(name)
					owner = nativead.DS_REPL_KCC_DSA_FAILURESW{}
				},
			}
			got, err := queryReplicationInfo(context.Background(), api, 17, kind, nil)
			if err != nil || len(got.failures) != 1 || freed != 1 {
				t.Fatalf("failures=%v free=%d err=%v", got.failures, freed, err)
			}
			failure := got.failures[0]
			if failure.PartnerDN == nil || *failure.PartnerDN != "CN=X" || failure.PartnerGUID != "0000007b-0000-0000-0000-000000000000" || failure.Time.Ticks == nil || *failure.Time.Ticks != 1<<32|42 || failure.FailureCount != 3 || failure.LastResult != 1722 || !failure.LastResultAvailable {
				t.Fatalf("lost native value: %+v", failure)
			}
			want := ReplicationConnectionFailure
			if kind == nativead.DS_REPL_INFO_KCC_DSA_LINK_FAILURES {
				want = ReplicationLinkFailure
			}
			if failure.Kind != want {
				t.Fatalf("kind=%v", failure.Kind)
			}
		})
	}
}

func TestReplicationNativeEmptyFailureAndCancelledOwnership(t *testing.T) {
	for _, mode := range []string{"empty", "failed", "cancelled", "null", "bad-count", "malformed-string"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			owner := nativead.DS_REPL_KCC_DSA_FAILURESW{}
			invalid := []uint16{0xd800, 0}
			freed := 0
			api := replicationAPI{getInfo: func(_ foundation.HANDLE, _ nativead.DS_REPL_INFO_TYPE, _ *string, _ *win32.GUID, _, _ *string, _, _ uint32, out *unsafe.Pointer) uint32 {
				if mode != "null" {
					*out = unsafe.Pointer(&owner)
				}
				switch mode {
				case "failed":
					return 8453
				case "cancelled":
					cancel()
				case "bad-count":
					owner.CNumEntries = 0xffffffff
				case "malformed-string":
					owner.CNumEntries = 1
					owner.RgDsaFailure[0].PszDsaDN = &invalid[0]
				}
				return 0
			}, freeInfo: func(_ nativead.DS_REPL_INFO_TYPE, _ unsafe.Pointer) { freed++ }}
			got, err := queryReplicationInfo(ctx, api, 17, nativead.DS_REPL_INFO_KCC_DSA_CONNECT_FAILURES, nil)
			wantFree := 1
			if mode == "null" {
				wantFree = 0
			}
			if freed != wantFree {
				t.Fatalf("free=%d want %d", freed, wantFree)
			}
			switch mode {
			case "empty":
				if err != nil || len(got.failures) != 0 {
					t.Fatalf("successful empty: %v, %v", got, err)
				}
			case "failed":
				var status *NativeStatusError
				if !errors.As(err, &status) || status.Code != 8453 {
					t.Fatalf("status lost: %v", err)
				}
			case "cancelled":
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation lost: %v", err)
				}
			default:
				if !errors.Is(err, ErrInvalidNativeResult) {
					t.Fatalf("invalid native result: %v", err)
				}
			}
		})
	}
}

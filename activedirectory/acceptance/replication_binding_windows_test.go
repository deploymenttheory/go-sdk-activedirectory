//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	nativead "github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/activedirectory"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestReplicationBindingOwnershipAndCancellation(t *testing.T) {
	for _, mode := range []string{"success", "credentials", "bind", "null-bind", "timeout", "query", "unbind", "cancel-before-bind", "cancel-after-query", "unsupported", "lds"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var trace []string
			credential := new(byte)
			owner := nativead.DS_REPL_KCC_DSA_FAILURESW{}
			api := admodel.InternalReplicationAPI{
				InternalFind: func(*win32.Proc) error {
					if mode == "unsupported" {
						return errors.New("missing export")
					}
					return nil
				},
				InternalCredentials: func(*admodel.Credentials) (unsafe.Pointer, error) {
					trace = append(trace, "credentials")
					if mode == "cancel-before-bind" {
						cancel()
					}
					if mode == "credentials" {
						return unsafe.Pointer(
								credential,
							), &admodel.NativeStatusError{
								Operation: "credentials",
								Code:      87,
							}
					}
					return unsafe.Pointer(credential), nil
				},
				InternalFreeCredentials: func(p unsafe.Pointer) {
					if p != unsafe.Pointer(credential) {
						t.Fatal("wrong credentials owner")
					}
					trace = append(trace, "free-credentials")
				},
				InternalBind: func(server, annotation *string, guid *win32.GUID, domain *string, identity unsafe.Pointer, spn *string, flags uint32, out *foundation.HANDLE) uint32 {
					trace = append(trace, "bind")
					if *server != "dc.example.test" || annotation != nil || domain != nil ||
						identity != unsafe.Pointer(credential) ||
						spn != nil ||
						flags != 0 {
						t.Fatal("wrong native bind parameters")
					}
					if (guid != nil) != (mode == "lds") {
						t.Fatal("LDS instance selection missing or invented")
					}
					if guid != nil && guid.Data1 != 0x04030201 {
						t.Fatal("incorrect GUID byte order")
					}
					if mode != "null-bind" {
						*out = 17
					}
					if mode == "bind" {
						return 1722
					}
					return 0
				},
				InternalUnBind: func(h *foundation.HANDLE) uint32 {
					trace = append(trace, "unbind")
					if *h != 17 {
						t.Fatal("wrong bind handle")
					}
					*h = 0
					if mode == "unbind" {
						return 6
					}
					return 0
				},
				InternalSetTimeout: func(h foundation.HANDLE, seconds uint32) uint32 {
					trace = append(trace, "timeout")
					if h != 17 || seconds != 1 {
						t.Fatalf("timeout %d %d", h, seconds)
					}
					if mode == "timeout" {
						return 87
					}
					return 0
				},
				InternalGetInfo: func(_ foundation.HANDLE, kind nativead.DS_REPL_INFO_TYPE, _ *string, _ *win32.GUID, _, _ *string, _, _ uint32, out *unsafe.Pointer) uint32 {
					trace = append(trace, "query")
					*out = unsafe.Pointer(&owner)
					if mode == "cancel-after-query" {
						cancel()
					}
					if mode == "query" && kind == nativead.DS_REPL_INFO_KCC_DSA_CONNECT_FAILURES {
						return 8453
					}
					return 0
				},
				InternalFreeInfo: func(_ nativead.DS_REPL_INFO_TYPE, p unsafe.Pointer) {
					trace = append(trace, "free-info")
					if p != unsafe.Pointer(&owner) {
						t.Fatal("wrong info owner")
					}
				},
			}
			root := admodel.RootDSE{
				SupportedCapabilities: []string{admodel.CapabilityActiveDirectory},
			}
			var instance []byte
			if mode == "lds" {
				root.SupportedCapabilities = []string{admodel.CapabilityADLDS}
				instance = []byte{1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			}
			credentials := &admodel.Credentials{
				Username: "synthetic",
				Domain:   "EXAMPLE",
				Password: []byte("synthetic-only"),
			}
			defer clear(credentials.Password)
			got, err := adengine.InternalReadReplicationWithAPI(
				ctx,
				admodel.Config{
					Endpoint:    admodel.Endpoint{Host: "dc.example.test"},
					Timeout:     time.Second,
					Credentials: credentials,
				},
				root,
				instance,
				admodel.InternalReplicationRequest{
					InternalKinds: []admodel.InternalReplicationInfo{
						admodel.InternalReplicationConnectFailures,
						admodel.InternalReplicationLinkFailures,
					},
				},
				api,
			)
			var want []string
			switch mode {
			case "unsupported":
				if !errors.Is(err, admodel.ErrUnsupported) {
					t.Fatalf("missing capability lost: %v", err)
				}
			case "credentials", "cancel-before-bind":
				want = []string{"credentials", "free-credentials"}
				if err == nil {
					t.Fatal("missing error")
				}
			case "null-bind":
				want = []string{"credentials", "bind", "free-credentials"}
				if !errors.Is(err, admodel.ErrInvalidNativeResult) {
					t.Fatalf("NULL bind: %v", err)
				}
			case "bind":
				want = []string{"credentials", "bind", "unbind", "free-credentials"}
				if err == nil {
					t.Fatal("bind failure lost")
				}
			case "timeout":
				want = []string{
					"credentials",
					"bind",
					"timeout",
					"timeout",
					"unbind",
					"free-credentials",
				}
				if got[admodel.InternalReplicationConnectFailures].InternalErr == nil ||
					got[admodel.InternalReplicationLinkFailures].InternalErr == nil {
					t.Fatal("timeout failure lost")
				}
			case "cancel-after-query":
				want = []string{
					"credentials",
					"bind",
					"timeout",
					"query",
					"free-info",
					"unbind",
					"free-credentials",
				}
				if !errors.Is(err, context.Canceled) ||
					!errors.Is(
						got[admodel.InternalReplicationLinkFailures].InternalErr,
						context.Canceled,
					) {
					t.Fatal("cancelled query continued")
				}
			default:
				want = []string{
					"credentials",
					"bind",
					"timeout",
					"query",
					"free-info",
					"timeout",
					"query",
					"free-info",
					"unbind",
					"free-credentials",
				}
				if (err != nil) != (mode == "unbind") {
					t.Fatalf("unexpected aggregate error %v", err)
				}
				if (got[admodel.InternalReplicationConnectFailures].InternalErr != nil) != (mode == "query") ||
					got[admodel.InternalReplicationLinkFailures].InternalErr != nil {
					t.Fatal("independent query failure/success lost")
				}
			}
			if !reflect.DeepEqual(trace, want) {
				t.Fatalf("native ownership trace=%v want=%v", trace, want)
			}
		})
	}
}

func TestReplicationNativeFlexibleQueueAndNeighborArrays(t *testing.T) {
	name := []uint16{'D', 'C', '=', 'x', 0}
	neighbors := struct {
		Count, Reserved uint32
		Rows            [2]nativead.DS_REPL_NEIGHBORW
	}{Count: 2}
	neighbors.Rows[0] = nativead.DS_REPL_NEIGHBORW{
		PszNamingContext:       &name[0],
		DwReplicaFlags:         0x80000000,
		UsnLastObjChangeSynced: -1,
		DwLastSyncResult:       1722,
	}
	neighbors.Rows[1] = nativead.DS_REPL_NEIGHBORW{CNumConsecutiveSyncFailures: 9}
	queue := struct {
		Started foundation.FILETIME
		Count   uint32
		Rows    [2]nativead.DS_REPL_OPW
	}{Started: foundation.FILETIME{DwLowDateTime: 1}, Count: 2}
	queue.Rows[0] = nativead.DS_REPL_OPW{
		UlSerialNumber:   44,
		UlPriority:       99,
		OpType:           nativead.DS_REPL_OP_TYPE(99),
		UlOptions:        0x80000000,
		PszNamingContext: &name[0],
	}
	queue.Rows[1] = nativead.DS_REPL_OPW{UlSerialNumber: 45}
	for _, kind := range []nativead.DS_REPL_INFO_TYPE{nativead.DS_REPL_INFO_NEIGHBORS, nativead.DS_REPL_INFO_PENDING_OPS} {
		freed := false
		api := admodel.InternalReplicationAPI{
			InternalGetInfo: func(_ foundation.HANDLE, _ nativead.DS_REPL_INFO_TYPE, _ *string, _ *win32.GUID, _, _ *string, _, _ uint32, out *unsafe.Pointer) uint32 {
				if kind == nativead.DS_REPL_INFO_NEIGHBORS {
					*out = unsafe.Pointer(&neighbors)
				} else {
					*out = unsafe.Pointer(&queue)
				}
				return 0
			},
			InternalFreeInfo: func(k nativead.DS_REPL_INFO_TYPE, _ unsafe.Pointer) {
				if k != kind {
					t.Fatal("mismatched free type")
				}
				freed = true
			},
		}
		got, err := admodel.InternalQueryReplicationInfo(context.Background(), api, 17, kind, nil)
		if err != nil || !freed {
			t.Fatalf("native result %v freed=%v", err, freed)
		}
		if kind == nativead.DS_REPL_INFO_NEIGHBORS {
			if len(got.InternalPartners) != 2 || *got.InternalPartners[0].LastObjectUSN != -1 ||
				*got.InternalPartners[0].ReplicaFlags != 0x80000000 ||
				got.InternalPartners[0].LastSuccess.Ticks == nil ||
				*got.InternalPartners[1].ConsecutiveFailures != 9 {
				t.Fatalf("neighbors=%+v", got.InternalPartners)
			}
		} else {
			if len(got.InternalOperations) != 2 || got.InternalOperations[0].SerialNumber != 44 ||
				got.InternalOperations[1].SerialNumber != 45 ||
				got.InternalOperations[0].Type != 99 ||
				got.InternalOperations[0].Options != 0x80000000 ||
				got.InternalStarted.Ticks == nil ||
				*got.InternalStarted.Ticks != 1 {
				t.Fatalf("queue=%+v", got)
			}
		}
	}
}

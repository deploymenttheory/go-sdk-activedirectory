//go:build windows && (amd64 || arm64)

package acceptance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestNativeWriteFailureOwnershipAndNoReplay(t *testing.T) {
	for _, mode := range []string{"accepted", "denied", "referral", "submit-failed", "result-failed", "wrong-kind", "nil-message", "parse-failed", "local-failed", "cleanup-failed", "canceled", "abandon-failed", "accepted-canceled", "unsupported", "timeout-option"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			session := &adengine.InternalLdapSession{
				InternalHandle:  new(ldap.LDAP),
				InternalTimeout: time.Second,
			}
			submits, polls, frees, names, abandons, closes := 0, 0, 0, 0, 0, 0
			session.InternalApi.InternalFind = func(*win32.Proc) error {
				if mode == "unsupported" {
					return admodel.ErrUnsupported
				}
				return nil
			}
			session.InternalApi.InternalSetOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 {
				if mode == "timeout-option" {
					return 82
				}
				return 0
			}
			session.InternalApi.InternalGetOption = func(_ *ldap.LDAP, _ int32, value unsafe.Pointer) uint32 { *(*uint32)(value) = 81; return 0 }
			session.InternalApi.InternalUnbind = func(*ldap.LDAP) uint32 { closes++; return 0 }
			session.InternalApi.InternalAbandon = func(_ *ldap.LDAP, id uint32) uint32 {
				abandons++
				if id != 17 {
					t.Fatal(id)
				}
				if mode == "abandon-failed" {
					return 82
				}
				return 0
			}
			session.InternalApi.InternalMessageFree = func(*ldap.LDAPMessage) uint32 {
				frees++
				if mode == "cleanup-failed" {
					return 82
				}
				return 0
			}
			session.InternalApi.InternalMemoryFree = func(foundation.PWSTR) { names++ }
			session.InternalApi.InternalResult = func(_ *ldap.LDAP, id, all uint32, _ *ldap.LDAP_TIMEVAL, message **ldap.LDAPMessage) uint32 {
				polls++
				if id != 17 || all != ldap.LDAP_MSG_ALL {
					t.Fatal("wrong pending request")
				}
				if mode == "canceled" || mode == "abandon-failed" {
					cancel()
					return 0
				}
				if mode != "nil-message" {
					*message = new(ldap.LDAPMessage)
				}
				if mode == "result-failed" {
					return math.MaxUint32
				}
				if mode == "wrong-kind" {
					return uint32(ldap.LDAP_RES_ADD)
				}
				if mode == "accepted-canceled" {
					cancel()
				}
				return uint32(ldap.LDAP_RES_MODIFY)
			}
			session.InternalApi.InternalParseResult = func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, dn, diag *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, free foundation.BOOLEAN) uint32 {
				if free != 0 {
					t.Fatal("parser unexpectedly owns message")
				}
				if mode == "parse-failed" {
					// Failure outputs are owned, but contents must not be copied.
					*dn, *diag = new(uint16), new(uint16)
					return 84
				}
				if mode == "denied" {
					*code = 50
					*diag = win32.UTF16Ptr("private native diagnostic")
				}
				if mode == "referral" {
					*code = 10
				}
				if mode == "local-failed" {
					*code = 81
				}
				return 0
			}
			api := adengine.InternalSystemLDAPWriteAPI()
			api.InternalModify = func(_ *ldap.LDAP, _ string, _ **ldap.LDAPModW, _, _ **ldap.LDAPControlW, id *uint32) uint32 {
				submits++
				*id = 17
				if mode == "submit-failed" {
					return 81
				}
				return 0
			}
			request := admodel.InternalLdapWriteRequest{
				InternalOperation: admodel.InternalLdapWriteModify,
				InternalDn:        "CN=test",
				InternalModifications: []admodel.InternalLdapAttributeModification{
					{InternalOperation: 1, InternalAttribute: "description"},
				},
			}
			attempt := session.InternalLdapWriteWith(ctx, request, api)
			wantState, wantClose, wantAbandon, wantFrees, wantNames := admodel.InternalLdapWriteUncertain, 1, 0, 1, 0
			switch mode {
			case "accepted", "accepted-canceled":
				wantState, wantClose = admodel.InternalLdapWriteAccepted, 0
			case "denied":
				wantState, wantClose, wantNames = admodel.InternalLdapWriteRejected, 0, 1
			case "referral":
				wantState, wantClose = admodel.InternalLdapWriteRejected, 0
			case "cleanup-failed":
				wantState = admodel.InternalLdapWriteAccepted
			case "submit-failed":
				wantFrees = 0
			case "parse-failed":
				wantNames = 2
			case "result-failed", "wrong-kind":
				wantAbandon = 1
			case "nil-message", "canceled", "abandon-failed":
				wantAbandon, wantFrees = 1, 0
			case "unsupported", "timeout-option":
				wantState, wantClose, wantFrees = admodel.InternalLdapWriteNotAttempted, 0, 0
			}
			wantSubmits := 1
			if wantState == admodel.InternalLdapWriteNotAttempted {
				wantSubmits = 0
			}
			if attempt.State != wantState || submits != wantSubmits || closes != wantClose ||
				abandons != wantAbandon ||
				frees != wantFrees ||
				names != wantNames {
				t.Fatalf(
					"attempt=%+v submits/polls=%d/%d close/abandon/free/names=%d/%d/%d/%d",
					attempt,
					submits,
					polls,
					closes,
					abandons,
					frees,
					names,
				)
			}
			if mode != "accepted" && attempt.Err == nil {
				t.Fatal("failure discarded")
			}
			if wantState == admodel.InternalLdapWriteUncertain &&
				(!errors.Is(attempt.Err, admodel.InternalLDAPWriteUncertainError()) || session.InternalHandle != nil) {
				t.Fatal("uncertain session remained usable", attempt)
			}
			if mode == "accepted-canceled" && !errors.Is(attempt.Err, context.Canceled) {
				t.Fatal("late cancellation lost", attempt)
			}
			if mode == "denied" {
				var native *admodel.LDAPError
				if !errors.As(attempt.Err, &native) || native.Code != 50 ||
					native.Diagnostic != "private native diagnostic" ||
					strings.Contains(attempt.Err.Error(), "private") {
					t.Fatal("native diagnostic ownership/privacy", attempt)
				}
			}
			if wantClose == 1 {
				next := session.InternalLdapWriteWith(context.Background(), request, api)
				if next.State != admodel.InternalLdapWriteNotAttempted ||
					!errors.Is(next.Err, admodel.ErrClosed) ||
					submits != 1 {
					t.Fatal("retired connection replayed", next, submits)
				}
			}
		})
	}
}

// Inspect actual LDAP protocol packets emitted by WinLDAP. Authentication and
// directory semantics are deliberately left to live AD qualification.
func TestNativeWriteWireEncodingAndOwnership(t *testing.T) {
	attribute := func(name string, values ...[]byte) []byte {
		var encoded [][]byte
		for _, value := range values {
			encoded = append(encoded, InternalSearchBER(4, value))
		}
		return InternalSearchBER(
			0x30,
			InternalSearchBER(4, []byte(name)),
			InternalSearchBER(0x31, encoded...),
		)
	}
	const dn = "CN=Dŵr,DC=example"
	var cases []struct {
		InternalOperation admodel.InternalLdapWriteOperation
		InternalCode      byte
	}
	for _, operation := range []admodel.InternalLdapWriteOperation{admodel.InternalLdapWriteAdd, admodel.InternalLdapWriteModify, admodel.InternalLdapWriteDelete, admodel.InternalLdapWriteRename} {
		for _, code := range []byte{0, 50} {
			cases = append(cases, struct {
				InternalOperation admodel.InternalLdapWriteOperation
				InternalCode      byte
			}{operation, code})
		}
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%d-code%d", tc.InternalOperation, tc.InternalCode), func(t *testing.T) {
			operation := tc.InternalOperation
			request := admodel.InternalLdapWriteRequest{
				InternalOperation: operation,
				InternalDn:        dn,
				InternalControls: []admodel.InternalLdapWriteControl{
					{
						InternalOid:      "1.2.840.113556.1.4.805",
						InternalCritical: true,
						InternalValue:    []byte{0, 255},
					},
				},
			}
			var tag, response byte
			var body []byte
			switch operation {
			case admodel.InternalLdapWriteAdd:
				request.InternalModifications = []admodel.InternalLdapAttributeModification{
					{
						InternalAttribute: "objectClass",
						InternalValues:    [][]byte{[]byte("top"), []byte("container")},
					},
					{InternalAttribute: "binary", InternalValues: [][]byte{{0, 255, 128}, {}}},
				}
				tag, response = 0x68, 0x69
				body = append(
					InternalSearchBER(4, []byte(dn)),
					InternalSearchBER(
						0x30,
						attribute("objectClass", []byte("top"), []byte("container")),
						attribute("binary", []byte{0, 255, 128}, []byte{}),
					)...)
			case admodel.InternalLdapWriteModify:
				request.InternalModifications = []admodel.InternalLdapAttributeModification{
					{
						InternalOperation: 0,
						InternalAttribute: "binary",
						InternalValues:    [][]byte{{0, 255, 128}, []byte("Dŵr")},
					},
					{InternalOperation: 1, InternalAttribute: "clear"},
					{
						InternalOperation: 2,
						InternalAttribute: "empty",
						InternalValues:    [][]byte{{}},
					},
				}
				tag, response = 0x66, 0x67
				body = append(
					InternalSearchBER(4, []byte(dn)),
					InternalSearchBER(
						0x30,
						InternalSearchBER(
							0x30,
							[]byte{10, 1, 0},
							attribute("binary", []byte{0, 255, 128}, []byte("Dŵr")),
						),
						InternalSearchBER(0x30, []byte{10, 1, 1}, attribute("clear")),
						InternalSearchBER(0x30, []byte{10, 1, 2}, attribute("empty", []byte{})),
					)...)
			case admodel.InternalLdapWriteDelete:
				tag, response, body = 0x4a, 0x6b, []byte(dn)
				request.InternalControls[0].InternalValue = nil // documented native tree-delete input: {0,NULL}
			case admodel.InternalLdapWriteRename:
				request.InternalNewRDN, request.InternalDeleteOldRDN = "CN=New Dŵr", true
				tag, response = 0x6c, 0x6d
				body = append(
					append(
						InternalSearchBER(4, []byte(dn)),
						InternalSearchBER(4, []byte("CN=New Dŵr"))...),
					[]byte{1, 1, 255}...)
			}
			controls := InternalSearchBER(
				0xa0,
				InternalSearchBER(
					0x30,
					InternalSearchBER(4, []byte("1.2.840.113556.1.4.805")),
					[]byte{1, 1, 255},
					InternalSearchBER(4, []byte{0, 255}),
				),
			)
			if operation == admodel.InternalLdapWriteDelete {
				// WinLDAP emits an empty OCTET STRING for the documented native
				// {0,NULL} control value. Do not claim that it omits this field.
				// learn.microsoft.com/previous-versions/windows/desktop/ldap/ldap-server-tree-delete-oid
				controls = InternalSearchBER(
					0xa0,
					InternalSearchBER(
						0x30,
						InternalSearchBER(4, []byte("1.2.840.113556.1.4.805")),
						[]byte{1, 1, 255},
						InternalSearchBER(4, nil),
					),
				)
			}
			fixture := InternalNewWriteWireFixture(
				t,
				tag,
				response,
				body,
				controls,
				tc.InternalCode,
			)
			var counts InternalSearchNativeCounts
			client := InternalSearchWireClient(
				t,
				&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
				InternalCountedSearchAPI(&counts),
			)
			(*adengine.InternalClientConfigPointer(client)).Timeout = 5 * time.Second
			var attempt admodel.InternalLdapWriteAttempt
			err := adengine.InternalClientRead(
				client,
				context.Background(),
				func(ctx context.Context) error {
					attempt = adengine.InternalClientSession(client).(*adengine.InternalLdapSession).InternalLdapWrite(
						ctx,
						request,
					)
					return attempt.Err
				},
			)
			if tc.InternalCode == 0 {
				if err != nil || attempt.State != admodel.InternalLdapWriteAccepted {
					t.Fatal(attempt, err)
				}
			} else {
				var native *admodel.LDAPError
				if attempt.State != admodel.InternalLdapWriteRejected || !errors.As(err, &native) ||
					native.Code != 50 ||
					native.Diagnostic != "private wire diagnostic" ||
					strings.Contains(err.Error(), "private") {
					t.Fatal("wire rejection lost", attempt, err)
				}
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if counts != (InternalSearchNativeCounts{}) {
				t.Fatalf("native allocation leak: %+v", counts)
			}
		})
	}
}

type InternalWriteWireFixture struct {
	InternalListener  net.Listener
	InternalMu        sync.Mutex
	InternalConn      net.Conn
	InternalSubmitted chan struct{}
}

func InternalNewWriteWireFixture(
	t *testing.T,
	requestTag, responseTag byte,
	wantBody, wantControls []byte,
	code byte,
) *InternalWriteWireFixture {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &InternalWriteWireFixture{
		InternalListener:  listener,
		InternalSubmitted: make(chan struct{}),
	}
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		f.InternalMu.Lock()
		f.InternalConn = conn
		f.InternalMu.Unlock()
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		count := 0
		for {
			packet, err := InternalReadSearchBER(conn)
			if err != nil {
				done <- err
				return
			}
			id, rest, err := InternalTakeSearchBER(packet, 2)
			if err != nil || len(rest) == 0 {
				done <- fmt.Errorf("invalid envelope: %w", err)
				return
			}
			if rest[0] == 0x42 {
				if count != 1 {
					done <- fmt.Errorf("write count %d", count)
				} else {
					done <- nil
				}
				return
			}
			if rest[0] == 0x50 {
				continue
			} // abandon never undoes the submitted write
			body, controls, err := InternalTakeSearchBER(rest, requestTag)
			if err != nil {
				done <- err
				return
			}
			// BER permits both minimal and padded definite lengths. Compare
			// decoded TLVs without normalizing primitive bytes or field order.
			canonicalBody, bodyErr := InternalCanonicalWriteBER(InternalSearchBER(requestTag, body))
			canonicalWant, wantErr := InternalCanonicalWriteBER(
				InternalSearchBER(requestTag, wantBody),
			)
			canonicalControls, controlErr := InternalCanonicalWriteBER(controls)
			if bodyErr != nil || wantErr != nil || controlErr != nil ||
				!bytes.Equal(canonicalBody, canonicalWant) ||
				!bytes.Equal(canonicalControls, wantControls) {
				done <- fmt.Errorf("wire mismatch: body %x want %x controls %x want %x", body, wantBody, controls, wantControls)
				return
			}
			count++
			if count == 1 {
				close(f.InternalSubmitted)
			}
			if code == 255 {
				continue
			} // fixture-only sentinel: never send a response
			var diagnostic []byte
			if code != 0 {
				diagnostic = []byte("private wire diagnostic")
			}
			if _, err := conn.Write(
				InternalSearchBER(
					0x30,
					InternalSearchBER(2, id),
					InternalSearchBER(
						responseTag,
						[]byte{10, 1, code},
						InternalSearchBER(4, nil),
						InternalSearchBER(4, diagnostic),
					),
				),
			); err != nil {
				done <- err
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		f.InternalMu.Lock()
		if f.InternalConn != nil {
			_ = f.InternalConn.Close()
		}
		f.InternalMu.Unlock()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) &&
				!errors.Is(err, syscall.WSAECONNRESET) {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("write responder did not stop")
		}
	})
	return f
}

func TestNativeWriteWireCancellationRetiresSession(t *testing.T) {
	fixture := InternalNewWriteWireFixture(t, 0x4a, 0x6b, []byte("CN=test"), nil, 255)
	var counts InternalSearchNativeCounts
	client := InternalSearchWireClient(
		t,
		&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
		InternalCountedSearchAPI(&counts),
	)
	(*adengine.InternalClientConfigPointer(client)).Timeout = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan admodel.InternalLdapWriteAttempt, 1)
	go func() {
		var attempt admodel.InternalLdapWriteAttempt
		_ = adengine.InternalClientRead(client, ctx, func(bounded context.Context) error {
			attempt = adengine.InternalClientSession(client).(*adengine.InternalLdapSession).InternalLdapWrite(
				bounded,
				admodel.InternalLdapWriteRequest{
					InternalOperation: admodel.InternalLdapWriteDelete,
					InternalDn:        "CN=test",
				},
			)
			return attempt.Err
		})
		finished <- attempt
	}()
	select {
	case <-fixture.InternalSubmitted:
		cancel()
	case <-time.After(5 * time.Second):
		t.Fatal("native request was not submitted")
	}
	select {
	case attempt := <-finished:
		if attempt.State != admodel.InternalLdapWriteUncertain ||
			!errors.Is(attempt.Err, context.Canceled) ||
			!errors.Is(attempt.Err, admodel.InternalLDAPWriteUncertainError()) ||
			adengine.InternalClientSession(client).(*adengine.InternalLdapSession).InternalHandle != nil {
			t.Fatal("canceled write remained usable", attempt)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native write did not finish after cancellation")
	}
	if counts != (InternalSearchNativeCounts{}) {
		t.Fatalf("cancellation leaked native ownership: %+v", counts)
	}
}

func InternalCanonicalWriteBER(encoded []byte) ([]byte, error) {
	var result []byte
	for len(encoded) > 0 {
		tag := encoded[0]
		body, rest, err := InternalTakeSearchBER(encoded, tag)
		if err != nil {
			return nil, err
		}
		if tag&0x20 != 0 {
			body, err = InternalCanonicalWriteBER(body)
			if err != nil {
				return nil, err
			}
		}
		result = append(result, InternalSearchBER(tag, body)...)
		encoded = rest
	}
	return result, nil
}

func TestNativeWriteMultipleValuesClearAndControls(t *testing.T) {
	session := &adengine.InternalLdapSession{
		InternalHandle:  new(ldap.LDAP),
		InternalTimeout: time.Second,
	}
	session.InternalApi.InternalFind = func(*win32.Proc) error { return nil }
	session.InternalApi.InternalSetOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 }
	session.InternalApi.InternalResult = func(_ *ldap.LDAP, id, all uint32, _ *ldap.LDAP_TIMEVAL, message **ldap.LDAPMessage) uint32 {
		if id != 17 || all != ldap.LDAP_MSG_ALL {
			t.Fatal("wrong response ownership")
		}
		*message = new(ldap.LDAPMessage)
		return uint32(ldap.LDAP_RES_MODIFY)
	}
	session.InternalApi.InternalParseResult = func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, _, _ *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, free foundation.BOOLEAN) uint32 {
		if free != 0 {
			t.Fatal("parser owns message")
		}
		*code = 0
		return 0
	}
	frees := 0
	session.InternalApi.InternalMessageFree = func(*ldap.LDAPMessage) uint32 { frees++; return 0 }
	request := admodel.InternalLdapWriteRequest{
		InternalOperation: admodel.InternalLdapWriteModify,
		InternalDn:        "CN=Dŵr,DC=test",
		InternalModifications: []admodel.InternalLdapAttributeModification{
			{
				InternalOperation: 0,
				InternalAttribute: "binary",
				InternalValues:    [][]byte{{0, 255, 128}, []byte("Dŵr")},
			},
			{InternalOperation: 1, InternalAttribute: "clear"},
			{InternalOperation: 2, InternalAttribute: "empty", InternalValues: [][]byte{{}}},
		},
		InternalControls: []admodel.InternalLdapWriteControl{
			{
				InternalOid:      "1.2.840.113556.1.4.805",
				InternalCritical: true,
				InternalValue:    []byte{0, 255},
			},
		},
	}
	calls := 0
	api := adengine.InternalSystemLDAPWriteAPI()
	api.InternalModify = func(_ *ldap.LDAP, dn string, mods **ldap.LDAPModW, server, client **ldap.LDAPControlW, id *uint32) uint32 {
		calls++
		runtime.GC()
		if dn != request.InternalDn || client != nil {
			t.Fatal("wrong target/client controls")
		}
		pointers := unsafe.Slice(mods, 4)
		if pointers[3] != nil {
			t.Fatal("missing mod terminator")
		}
		for i, want := range request.InternalModifications {
			mod := pointers[i]
			name, err := adengine.InternalCopyLDAPText(mod.Mod_type)
			if err != nil || name != want.InternalAttribute ||
				mod.Mod_op != want.InternalOperation|ldap.LDAP_MOD_BVALUES {
				t.Fatal("wrong modification", i)
			}
			ptr := *(***ldap.LDAP_BERVAL)(unsafe.Pointer(&mod.Mod_vals))
			if len(want.InternalValues) == 0 {
				if ptr != nil {
					t.Fatal("clear must use NULL union")
				}
				continue
			}
			values := unsafe.Slice(ptr, len(want.InternalValues)+1)
			if values[len(want.InternalValues)] != nil {
				t.Fatal("missing value terminator")
			}
			for j, value := range want.InternalValues {
				if values[j] == nil ||
					!bytes.Equal(
						unsafe.Slice(
							(*byte)(unsafe.Pointer(values[j].Bv_val)),
							int(values[j].Bv_len),
						),
						value,
					) {
					t.Fatal("binary/empty value changed", i, j)
				}
			}
		}
		controls := unsafe.Slice(server, 2)
		oid, err := adengine.InternalCopyLDAPText(controls[0].Ldctl_oid)
		if controls[1] != nil || err != nil || oid != request.InternalControls[0].InternalOid ||
			controls[0].Ldctl_iscritical != 1 ||
			!bytes.Equal(
				unsafe.Slice(
					(*byte)(unsafe.Pointer(controls[0].Ldctl_value.Bv_val)),
					int(controls[0].Ldctl_value.Bv_len),
				),
				[]byte{0, 255},
			) {
			t.Fatal("control changed across GC")
		}
		*id = 17
		return 0
	}
	attempt := session.InternalLdapWriteWith(context.Background(), request, api)
	if attempt.State != admodel.InternalLdapWriteAccepted || attempt.Err != nil || calls != 1 ||
		frees != 1 {
		t.Fatalf("attempt=%+v calls=%d frees=%d", attempt, calls, frees)
	}
}

func TestNativeWriteLegacyNilValueIsNotClear(t *testing.T) {
	session := &adengine.InternalLdapSession{
		InternalHandle:  new(ldap.LDAP),
		InternalTimeout: time.Second,
	}
	session.InternalApi.InternalFind = func(*win32.Proc) error { return nil }
	session.InternalApi.InternalSetOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 }
	closes, calls := 0, 0
	session.InternalApi.InternalUnbind = func(*ldap.LDAP) uint32 { closes++; return 0 }
	attempt := session.InternalLdapModifyWith(
		context.Background(),
		"",
		[]admodel.InternalLdapModification{
			{InternalOperation: 1, InternalAttribute: "description", InternalValue: nil},
		},
		func(_ *ldap.LDAP, dn string, mods **ldap.LDAPModW, server, client **ldap.LDAPControlW, _ *uint32) uint32 {
			calls++
			runtime.GC()
			pointers := unsafe.Slice(mods, 2)
			values := *(***ldap.LDAP_BERVAL)(unsafe.Pointer(&pointers[0].Mod_vals))
			if dn != "" || pointers[1] != nil || server != nil || client != nil || values == nil ||
				*values == nil ||
				(*values).Bv_len != 0 ||
				unsafe.Slice(values, 2)[1] != nil {
				t.Fatal("legacy nil value became an attribute clear")
			}
			return 81
		},
	)
	var native *admodel.LDAPError
	if attempt.State != admodel.InternalLdapWriteUncertain || !errors.As(attempt.Err, &native) ||
		native.Operation != "ldap_modify_extW" ||
		calls != 1 ||
		closes != 1 {
		t.Fatal(attempt, calls, closes)
	}
}

func TestNativeWriteInvalidInputsNeverDispatch(t *testing.T) {
	for _, request := range []admodel.InternalLdapWriteRequest{
		{InternalOperation: 255, InternalDn: "CN=test"},
		{InternalOperation: admodel.InternalLdapWriteDelete},
		{InternalOperation: admodel.InternalLdapWriteDelete, InternalDn: "CN=test\x00"},
		{InternalOperation: admodel.InternalLdapWriteDelete, InternalDn: "CN=test", InternalModifications: []admodel.InternalLdapAttributeModification{{InternalAttribute: "name", InternalValues: [][]byte{[]byte("x")}}}},
		{InternalOperation: admodel.InternalLdapWriteRename, InternalDn: "CN=test"},
		{InternalOperation: admodel.InternalLdapWriteRename, InternalDn: "CN=test", InternalNewRDN: "CN=x\x00"},
		{InternalOperation: admodel.InternalLdapWriteModify, InternalDn: "CN=test", InternalModifications: []admodel.InternalLdapAttributeModification{{InternalOperation: 2, InternalAttribute: "name"}}},
		{InternalOperation: admodel.InternalLdapWriteModify, InternalDn: "CN=test", InternalModifications: []admodel.InternalLdapAttributeModification{{InternalOperation: 3, InternalAttribute: "name", InternalValues: [][]byte{{1}}}}},
		{InternalOperation: admodel.InternalLdapWriteAdd, InternalDn: "CN=test", InternalModifications: []admodel.InternalLdapAttributeModification{{InternalOperation: 1, InternalAttribute: "name"}}},
		{InternalOperation: admodel.InternalLdapWriteDelete, InternalDn: "CN=test", InternalControls: []admodel.InternalLdapWriteControl{{InternalOid: "1.2.3\x00"}}},
	} {
		// A boundary call would panic: validation must precede every native call.
		attempt := (&adengine.InternalLdapSession{InternalHandle: new(ldap.LDAP)}).InternalLdapWriteWith(
			context.Background(),
			request,
			adengine.InternalLdapWriteAPI{},
		)
		if attempt.State != admodel.InternalLdapWriteNotAttempted || attempt.Err == nil {
			t.Fatal("invalid request submitted", request, attempt)
		}
	}
}

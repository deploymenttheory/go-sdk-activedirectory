//go:build windows && (amd64 || arm64)

package activedirectory

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
)

func TestNativeWriteFailureOwnershipAndNoReplay(t *testing.T) {
	for _, mode := range []string{"accepted", "denied", "referral", "submit-failed", "result-failed", "wrong-kind", "nil-message", "parse-failed", "local-failed", "cleanup-failed", "canceled", "abandon-failed", "accepted-canceled", "unsupported", "timeout-option"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			session := &ldapSession{handle: new(ldap.LDAP), timeout: time.Second}
			submits, polls, frees, names, abandons, closes := 0, 0, 0, 0, 0, 0
			session.api.find = func(*win32.Proc) error {
				if mode == "unsupported" {
					return ErrUnsupported
				}
				return nil
			}
			session.api.setOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 {
				if mode == "timeout-option" {
					return 82
				}
				return 0
			}
			session.api.getOption = func(_ *ldap.LDAP, _ int32, value unsafe.Pointer) uint32 { *(*uint32)(value) = 81; return 0 }
			session.api.unbind = func(*ldap.LDAP) uint32 { closes++; return 0 }
			session.api.abandon = func(_ *ldap.LDAP, id uint32) uint32 {
				abandons++
				if id != 17 {
					t.Fatal(id)
				}
				if mode == "abandon-failed" {
					return 82
				}
				return 0
			}
			session.api.messageFree = func(*ldap.LDAPMessage) uint32 {
				frees++
				if mode == "cleanup-failed" {
					return 82
				}
				return 0
			}
			session.api.memoryFree = func(foundation.PWSTR) { names++ }
			session.api.result = func(_ *ldap.LDAP, id, all uint32, _ *ldap.LDAP_TIMEVAL, message **ldap.LDAPMessage) uint32 {
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
			session.api.parseResult = func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, dn, diag *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, free foundation.BOOLEAN) uint32 {
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
			api := systemLDAPWriteAPI()
			api.modify = func(_ *ldap.LDAP, _ string, _ **ldap.LDAPModW, _, _ **ldap.LDAPControlW, id *uint32) uint32 {
				submits++
				*id = 17
				if mode == "submit-failed" {
					return 81
				}
				return 0
			}
			request := ldapWriteRequest{operation: ldapWriteModify, dn: "CN=test", modifications: []ldapAttributeModification{{operation: 1, attribute: "description"}}}
			attempt := session.ldapWriteWith(ctx, request, api)
			wantState, wantClose, wantAbandon, wantFrees, wantNames := ldapWriteUncertain, 1, 0, 1, 0
			switch mode {
			case "accepted", "accepted-canceled":
				wantState, wantClose = ldapWriteAccepted, 0
			case "denied":
				wantState, wantClose, wantNames = ldapWriteRejected, 0, 1
			case "referral":
				wantState, wantClose = ldapWriteRejected, 0
			case "cleanup-failed":
				wantState = ldapWriteAccepted
			case "submit-failed":
				wantFrees = 0
			case "parse-failed":
				wantNames = 2
			case "result-failed", "wrong-kind":
				wantAbandon = 1
			case "nil-message", "canceled", "abandon-failed":
				wantAbandon, wantFrees = 1, 0
			case "unsupported", "timeout-option":
				wantState, wantClose, wantFrees = ldapWriteNotAttempted, 0, 0
			}
			wantSubmits := 1
			if wantState == ldapWriteNotAttempted {
				wantSubmits = 0
			}
			if attempt.State != wantState || submits != wantSubmits || closes != wantClose || abandons != wantAbandon || frees != wantFrees || names != wantNames {
				t.Fatalf("attempt=%+v submits/polls=%d/%d close/abandon/free/names=%d/%d/%d/%d", attempt, submits, polls, closes, abandons, frees, names)
			}
			if mode != "accepted" && attempt.Err == nil {
				t.Fatal("failure discarded")
			}
			if wantState == ldapWriteUncertain && (!errors.Is(attempt.Err, errLDAPWriteUncertain) || session.handle != nil) {
				t.Fatal("uncertain session remained usable", attempt)
			}
			if mode == "accepted-canceled" && !errors.Is(attempt.Err, context.Canceled) {
				t.Fatal("late cancellation lost", attempt)
			}
			if mode == "denied" {
				var native *LDAPError
				if !errors.As(attempt.Err, &native) || native.Code != 50 || native.Diagnostic != "private native diagnostic" || strings.Contains(attempt.Err.Error(), "private") {
					t.Fatal("native diagnostic ownership/privacy", attempt)
				}
			}
			if wantClose == 1 {
				next := session.ldapWriteWith(context.Background(), request, api)
				if next.State != ldapWriteNotAttempted || !errors.Is(next.Err, ErrClosed) || submits != 1 {
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
			encoded = append(encoded, searchBER(4, value))
		}
		return searchBER(0x30, searchBER(4, []byte(name)), searchBER(0x31, encoded...))
	}
	const dn = "CN=Dŵr,DC=example"
	var cases []struct {
		operation ldapWriteOperation
		code      byte
	}
	for _, operation := range []ldapWriteOperation{ldapWriteAdd, ldapWriteModify, ldapWriteDelete, ldapWriteRename} {
		for _, code := range []byte{0, 50} {
			cases = append(cases, struct {
				operation ldapWriteOperation
				code      byte
			}{operation, code})
		}
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%d-code%d", tc.operation, tc.code), func(t *testing.T) {
			operation := tc.operation
			request := ldapWriteRequest{operation: operation, dn: dn, controls: []ldapWriteControl{{oid: "1.2.840.113556.1.4.805", critical: true, value: []byte{0, 255}}}}
			var tag, response byte
			var body []byte
			switch operation {
			case ldapWriteAdd:
				request.modifications = []ldapAttributeModification{{attribute: "objectClass", values: [][]byte{[]byte("top"), []byte("container")}}, {attribute: "binary", values: [][]byte{{0, 255, 128}, {}}}}
				tag, response = 0x68, 0x69
				body = append(searchBER(4, []byte(dn)), searchBER(0x30, attribute("objectClass", []byte("top"), []byte("container")), attribute("binary", []byte{0, 255, 128}, []byte{}))...)
			case ldapWriteModify:
				request.modifications = []ldapAttributeModification{{operation: 0, attribute: "binary", values: [][]byte{{0, 255, 128}, []byte("Dŵr")}}, {operation: 1, attribute: "clear"}, {operation: 2, attribute: "empty", values: [][]byte{{}}}}
				tag, response = 0x66, 0x67
				body = append(searchBER(4, []byte(dn)), searchBER(0x30, searchBER(0x30, []byte{10, 1, 0}, attribute("binary", []byte{0, 255, 128}, []byte("Dŵr"))), searchBER(0x30, []byte{10, 1, 1}, attribute("clear")), searchBER(0x30, []byte{10, 1, 2}, attribute("empty", []byte{})))...)
			case ldapWriteDelete:
				tag, response, body = 0x4a, 0x6b, []byte(dn)
				request.controls[0].value = nil // documented native tree-delete input: {0,NULL}
			case ldapWriteRename:
				request.newRDN, request.deleteOldRDN = "CN=New Dŵr", true
				tag, response = 0x6c, 0x6d
				body = append(append(searchBER(4, []byte(dn)), searchBER(4, []byte("CN=New Dŵr"))...), []byte{1, 1, 255}...)
			}
			controls := searchBER(0xa0, searchBER(0x30, searchBER(4, []byte("1.2.840.113556.1.4.805")), []byte{1, 1, 255}, searchBER(4, []byte{0, 255})))
			if operation == ldapWriteDelete {
				// WinLDAP emits an empty OCTET STRING for the documented native
				// {0,NULL} control value. Do not claim that it omits this field.
				// learn.microsoft.com/previous-versions/windows/desktop/ldap/ldap-server-tree-delete-oid
				controls = searchBER(0xa0, searchBER(0x30, searchBER(4, []byte("1.2.840.113556.1.4.805")), []byte{1, 1, 255}, searchBER(4, nil)))
			}
			fixture := newWriteWireFixture(t, tag, response, body, controls, tc.code)
			var counts searchNativeCounts
			client := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&counts))
			client.config.Timeout = 5 * time.Second
			var attempt ldapWriteAttempt
			err := client.read(context.Background(), func(ctx context.Context) error {
				attempt = client.session.(*ldapSession).ldapWrite(ctx, request)
				return attempt.Err
			})
			if tc.code == 0 {
				if err != nil || attempt.State != ldapWriteAccepted {
					t.Fatal(attempt, err)
				}
			} else {
				var native *LDAPError
				if attempt.State != ldapWriteRejected || !errors.As(err, &native) || native.Code != 50 || native.Diagnostic != "private wire diagnostic" || strings.Contains(err.Error(), "private") {
					t.Fatal("wire rejection lost", attempt, err)
				}
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if counts != (searchNativeCounts{}) {
				t.Fatalf("native allocation leak: %+v", counts)
			}
		})
	}
}

type writeWireFixture struct {
	listener  net.Listener
	mu        sync.Mutex
	conn      net.Conn
	submitted chan struct{}
}

func newWriteWireFixture(t *testing.T, requestTag, responseTag byte, wantBody, wantControls []byte, code byte) *writeWireFixture {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &writeWireFixture{listener: listener, submitted: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		f.mu.Lock()
		f.conn = conn
		f.mu.Unlock()
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		count := 0
		for {
			packet, err := readSearchBER(conn)
			if err != nil {
				done <- err
				return
			}
			id, rest, err := takeSearchBER(packet, 2)
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
			body, controls, err := takeSearchBER(rest, requestTag)
			if err != nil {
				done <- err
				return
			}
			// BER permits both minimal and padded definite lengths. Compare
			// decoded TLVs without normalizing primitive bytes or field order.
			canonicalBody, bodyErr := canonicalWriteBER(searchBER(requestTag, body))
			canonicalWant, wantErr := canonicalWriteBER(searchBER(requestTag, wantBody))
			canonicalControls, controlErr := canonicalWriteBER(controls)
			if bodyErr != nil || wantErr != nil || controlErr != nil || !bytes.Equal(canonicalBody, canonicalWant) || !bytes.Equal(canonicalControls, wantControls) {
				done <- fmt.Errorf("wire mismatch: body %x want %x controls %x want %x", body, wantBody, controls, wantControls)
				return
			}
			count++
			if count == 1 {
				close(f.submitted)
			}
			if code == 255 {
				continue
			} // fixture-only sentinel: never send a response
			var diagnostic []byte
			if code != 0 {
				diagnostic = []byte("private wire diagnostic")
			}
			if _, err := conn.Write(searchBER(0x30, searchBER(2, id), searchBER(responseTag, []byte{10, 1, code}, searchBER(4, nil), searchBER(4, diagnostic)))); err != nil {
				done <- err
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		f.mu.Lock()
		if f.conn != nil {
			_ = f.conn.Close()
		}
		f.mu.Unlock()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, syscall.WSAECONNRESET) {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("write responder did not stop")
		}
	})
	return f
}

func TestNativeWriteWireCancellationRetiresSession(t *testing.T) {
	fixture := newWriteWireFixture(t, 0x4a, 0x6b, []byte("CN=test"), nil, 255)
	var counts searchNativeCounts
	client := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&counts))
	client.config.Timeout = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan ldapWriteAttempt, 1)
	go func() {
		var attempt ldapWriteAttempt
		_ = client.read(ctx, func(bounded context.Context) error {
			attempt = client.session.(*ldapSession).ldapWrite(bounded, ldapWriteRequest{operation: ldapWriteDelete, dn: "CN=test"})
			return attempt.Err
		})
		finished <- attempt
	}()
	select {
	case <-fixture.submitted:
		cancel()
	case <-time.After(5 * time.Second):
		t.Fatal("native request was not submitted")
	}
	select {
	case attempt := <-finished:
		if attempt.State != ldapWriteUncertain || !errors.Is(attempt.Err, context.Canceled) || !errors.Is(attempt.Err, errLDAPWriteUncertain) || client.session.(*ldapSession).handle != nil {
			t.Fatal("canceled write remained usable", attempt)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native write did not finish after cancellation")
	}
	if counts != (searchNativeCounts{}) {
		t.Fatalf("cancellation leaked native ownership: %+v", counts)
	}
}

func canonicalWriteBER(encoded []byte) ([]byte, error) {
	var result []byte
	for len(encoded) > 0 {
		tag := encoded[0]
		body, rest, err := takeSearchBER(encoded, tag)
		if err != nil {
			return nil, err
		}
		if tag&0x20 != 0 {
			body, err = canonicalWriteBER(body)
			if err != nil {
				return nil, err
			}
		}
		result = append(result, searchBER(tag, body)...)
		encoded = rest
	}
	return result, nil
}

func TestNativeWriteMultipleValuesClearAndControls(t *testing.T) {
	session := &ldapSession{handle: new(ldap.LDAP), timeout: time.Second}
	session.api.find = func(*win32.Proc) error { return nil }
	session.api.setOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 }
	session.api.result = func(_ *ldap.LDAP, id, all uint32, _ *ldap.LDAP_TIMEVAL, message **ldap.LDAPMessage) uint32 {
		if id != 17 || all != ldap.LDAP_MSG_ALL {
			t.Fatal("wrong response ownership")
		}
		*message = new(ldap.LDAPMessage)
		return uint32(ldap.LDAP_RES_MODIFY)
	}
	session.api.parseResult = func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, _, _ *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, free foundation.BOOLEAN) uint32 {
		if free != 0 {
			t.Fatal("parser owns message")
		}
		*code = 0
		return 0
	}
	frees := 0
	session.api.messageFree = func(*ldap.LDAPMessage) uint32 { frees++; return 0 }
	request := ldapWriteRequest{operation: ldapWriteModify, dn: "CN=Dŵr,DC=test", modifications: []ldapAttributeModification{
		{operation: 0, attribute: "binary", values: [][]byte{{0, 255, 128}, []byte("Dŵr")}},
		{operation: 1, attribute: "clear"},
		{operation: 2, attribute: "empty", values: [][]byte{{}}},
	}, controls: []ldapWriteControl{{oid: "1.2.840.113556.1.4.805", critical: true, value: []byte{0, 255}}}}
	calls := 0
	api := systemLDAPWriteAPI()
	api.modify = func(_ *ldap.LDAP, dn string, mods **ldap.LDAPModW, server, client **ldap.LDAPControlW, id *uint32) uint32 {
		calls++
		runtime.GC()
		if dn != request.dn || client != nil {
			t.Fatal("wrong target/client controls")
		}
		pointers := unsafe.Slice(mods, 4)
		if pointers[3] != nil {
			t.Fatal("missing mod terminator")
		}
		for i, want := range request.modifications {
			mod := pointers[i]
			name, err := copyLDAPText(mod.Mod_type)
			if err != nil || name != want.attribute || mod.Mod_op != want.operation|ldap.LDAP_MOD_BVALUES {
				t.Fatal("wrong modification", i)
			}
			ptr := *(***ldap.LDAP_BERVAL)(unsafe.Pointer(&mod.Mod_vals))
			if len(want.values) == 0 {
				if ptr != nil {
					t.Fatal("clear must use NULL union")
				}
				continue
			}
			values := unsafe.Slice(ptr, len(want.values)+1)
			if values[len(want.values)] != nil {
				t.Fatal("missing value terminator")
			}
			for j, value := range want.values {
				if values[j] == nil || !bytes.Equal(unsafe.Slice((*byte)(unsafe.Pointer(values[j].Bv_val)), int(values[j].Bv_len)), value) {
					t.Fatal("binary/empty value changed", i, j)
				}
			}
		}
		controls := unsafe.Slice(server, 2)
		oid, err := copyLDAPText(controls[0].Ldctl_oid)
		if controls[1] != nil || err != nil || oid != request.controls[0].oid || controls[0].Ldctl_iscritical != 1 || !bytes.Equal(unsafe.Slice((*byte)(unsafe.Pointer(controls[0].Ldctl_value.Bv_val)), int(controls[0].Ldctl_value.Bv_len)), []byte{0, 255}) {
			t.Fatal("control changed across GC")
		}
		*id = 17
		return 0
	}
	attempt := session.ldapWriteWith(context.Background(), request, api)
	if attempt.State != ldapWriteAccepted || attempt.Err != nil || calls != 1 || frees != 1 {
		t.Fatalf("attempt=%+v calls=%d frees=%d", attempt, calls, frees)
	}
}

func TestNativeWriteLegacyNilValueIsNotClear(t *testing.T) {
	session := &ldapSession{handle: new(ldap.LDAP), timeout: time.Second}
	session.api.find = func(*win32.Proc) error { return nil }
	session.api.setOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 }
	closes, calls := 0, 0
	session.api.unbind = func(*ldap.LDAP) uint32 { closes++; return 0 }
	attempt := session.ldapModifyWith(context.Background(), "", []ldapModification{{operation: 1, attribute: "description", value: nil}}, func(_ *ldap.LDAP, dn string, mods **ldap.LDAPModW, server, client **ldap.LDAPControlW, _ *uint32) uint32 {
		calls++
		runtime.GC()
		pointers := unsafe.Slice(mods, 2)
		values := *(***ldap.LDAP_BERVAL)(unsafe.Pointer(&pointers[0].Mod_vals))
		if dn != "" || pointers[1] != nil || server != nil || client != nil || values == nil || *values == nil || (*values).Bv_len != 0 || unsafe.Slice(values, 2)[1] != nil {
			t.Fatal("legacy nil value became an attribute clear")
		}
		return 81
	})
	var native *LDAPError
	if attempt.State != ldapWriteUncertain || !errors.As(attempt.Err, &native) || native.Operation != "ldap_modify_extW" || calls != 1 || closes != 1 {
		t.Fatal(attempt, calls, closes)
	}
}

func TestNativeWriteInvalidInputsNeverDispatch(t *testing.T) {
	for _, request := range []ldapWriteRequest{
		{operation: 255, dn: "CN=test"},
		{operation: ldapWriteDelete},
		{operation: ldapWriteDelete, dn: "CN=test\x00"},
		{operation: ldapWriteDelete, dn: "CN=test", modifications: []ldapAttributeModification{{attribute: "name", values: [][]byte{[]byte("x")}}}},
		{operation: ldapWriteRename, dn: "CN=test"},
		{operation: ldapWriteRename, dn: "CN=test", newRDN: "CN=x\x00"},
		{operation: ldapWriteModify, dn: "CN=test", modifications: []ldapAttributeModification{{operation: 2, attribute: "name"}}},
		{operation: ldapWriteModify, dn: "CN=test", modifications: []ldapAttributeModification{{operation: 3, attribute: "name", values: [][]byte{{1}}}}},
		{operation: ldapWriteAdd, dn: "CN=test", modifications: []ldapAttributeModification{{operation: 1, attribute: "name"}}},
		{operation: ldapWriteDelete, dn: "CN=test", controls: []ldapWriteControl{{oid: "1.2.3\x00"}}},
	} {
		// A boundary call would panic: validation must precede every native call.
		attempt := (&ldapSession{handle: new(ldap.LDAP)}).ldapWriteWith(context.Background(), request, ldapWriteAPI{})
		if attempt.State != ldapWriteNotAttempted || attempt.Err == nil {
			t.Fatal("invalid request submitted", request, attempt)
		}
	}
}

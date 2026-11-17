//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// The loopback responder controls wire-level page boundaries and error results.
// The SDK uses real WinLDAP allocation, parsing, copying, polling and cleanup.
// Authentication is intentionally outside this fixture and covered by AD labs.
type InternalSearchWirePage struct {
	InternalCount       int
	InternalCode        byte
	InternalEmptyCookie bool
	InternalStall       bool
	InternalRanged      bool
	InternalOmitControl bool
	InternalReference   bool
	// Optional base-object responses exercise the same real WinLDAP parser
	// without requiring a paged-search control.
	InternalBaseRead   bool
	InternalDn         string
	InternalAttributes map[string][][]byte
}
type InternalSearchWireFixture struct {
	InternalListener     net.Listener
	InternalMu           sync.Mutex
	InternalConn         net.Conn
	InternalSizes        []int
	InternalFilters      [][]byte
	InternalPages        []InternalSearchWirePage
	InternalDone         chan error
	InternalStallCleanup bool
	// Only tests that deliberately close before reading a submitted response
	// permit a local WSAECONNABORTED while the responder is sending that response.
	InternalAllowAbortedClose bool
}

func InternalNewSearchWireFixture(
	t *testing.T,
	pages []InternalSearchWirePage,
) *InternalSearchWireFixture {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &InternalSearchWireFixture{
		InternalListener: listener,
		InternalPages:    pages,
		InternalDone:     make(chan error, 1),
	}
	go func() { f.InternalDone <- f.InternalServe() }()
	t.Cleanup(func() {
		_ = listener.Close()
		f.InternalMu.Lock()
		if f.InternalConn != nil {
			_ = f.InternalConn.Close()
		}
		f.InternalMu.Unlock()
		select {
		case err := <-f.InternalDone:
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) &&
				!errors.Is(err, syscall.WSAECONNRESET) &&
				!(f.InternalAllowAbortedClose && errors.Is(err, syscall.WSAECONNABORTED)) {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("loopback LDAP responder did not stop")
		}
	})
	return f
}

func (f *InternalSearchWireFixture) InternalServe() error {
	conn, err := f.InternalListener.Accept()
	if err != nil {
		return err
	}
	f.InternalMu.Lock()
	f.InternalConn = conn
	f.InternalMu.Unlock()
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	pageIndex := 0
	for {
		packet, err := InternalReadSearchBER(conn)
		if err != nil {
			return err
		}
		id, rest, err := InternalTakeSearchBER(packet, 2)
		if err != nil || len(rest) < 2 {
			return fmt.Errorf("invalid LDAP envelope: %v", err)
		}
		if rest[0] == 0x42 {
			return nil
		} // unbind
		if rest[0] == 0x50 {
			continue
		} // abandon
		request, controls, err := InternalTakeSearchBER(rest, 0x63)
		if err != nil {
			return err
		}
		base, _, err := InternalTakeSearchBER(request, 4)
		if err != nil {
			return err
		}
		messageID := InternalSearchBER(2, id)
		if len(base) == 0 {
			entry := InternalSearchBER(
				0x64,
				InternalSearchBER(4, nil),
				InternalSearchBER(
					0x30,
					InternalSearchWireAttribute(
						"supportedControl",
						[]byte("1.2.840.113556.1.4.319"),
					),
				),
			)
			if _, err := conn.Write(InternalSearchBER(0x30, messageID, entry)); err != nil {
				return err
			}
			if _, err := conn.Write(
				InternalSearchBER(
					0x30,
					messageID,
					InternalSearchBER(0x65, []byte{10, 1, 0, 4, 0, 4, 0}),
				),
			); err != nil {
				return err
			}
			continue
		}
		size := 1
		if len(controls) != 0 || pageIndex >= len(f.InternalPages) ||
			!f.InternalPages[pageIndex].InternalBaseRead {
			size, err = InternalSearchWirePageSize(controls)
		}
		if err != nil {
			return err
		}
		filter, err := InternalSearchWireFilter(request)
		if err != nil {
			return err
		}
		f.InternalMu.Lock()
		f.InternalSizes = append(f.InternalSizes, size)
		f.InternalFilters = append(f.InternalFilters, filter)
		f.InternalMu.Unlock()
		if size == 0 {
			f.InternalMu.Lock()
			stallCleanup := f.InternalStallCleanup
			f.InternalMu.Unlock()
			if !stallCleanup {
				control := InternalSearchBER(
					0xa0,
					InternalSearchBER(
						0x30,
						InternalSearchBER(4, []byte("1.2.840.113556.1.4.319")),
						InternalSearchBER(4, InternalSearchBER(0x30, []byte{2, 1, 0, 4, 0})),
					),
				)
				if _, err := conn.Write(
					InternalSearchBER(
						0x30,
						messageID,
						InternalSearchBER(0x65, []byte{10, 1, 0, 4, 0, 4, 0}),
						control,
					),
				); err != nil {
					return err
				}
			}
			continue
		} // release server cookie
		if pageIndex >= len(f.InternalPages) {
			return fmt.Errorf("unexpected page request %d", pageIndex)
		}
		page := f.InternalPages[pageIndex]
		pageIndex++
		if page.InternalStall {
			continue
		}
		if page.InternalReference {
			if _, err := conn.Write(
				InternalSearchBER(
					0x30,
					messageID,
					InternalSearchBER(
						0x73,
						InternalSearchBER(4, []byte("ldap://other.invalid/DC=else")),
					),
				),
			); err != nil {
				return err
			}
		}
		for i := 0; i < page.InternalCount; i++ {
			attrs := InternalSearchBER(
				0x30,
				InternalSearchWireAttribute(
					"objectGUID",
					[]byte{0, 255, 128, byte(pageIndex), byte(i)},
				),
				InternalSearchWireAttribute(
					"name",
					[]byte(fmt.Sprintf("object-%d-%d", pageIndex, i)),
				),
			)
			if page.InternalRanged {
				attrs = InternalSearchBER(
					0x30,
					InternalSearchWireAttribute(
						"member;range=0-1499",
						[]byte("CN=first,DC=example"),
					),
				)
			}
			if page.InternalAttributes != nil {
				var encoded [][]byte
				for name, values := range page.InternalAttributes {
					encoded = append(encoded, InternalSearchWireAttribute(name, values...))
				}
				attrs = InternalSearchBER(0x30, encoded...)
			}
			dn := page.InternalDn
			if dn == "" {
				dn = fmt.Sprintf("CN=object-%d-%d,DC=example", pageIndex, i)
			}
			entry := InternalSearchBER(0x64, InternalSearchBER(4, []byte(dn)), attrs)
			if _, err := conn.Write(InternalSearchBER(0x30, messageID, entry)); err != nil {
				return err
			}
		}
		cookie := []byte(strconv.Itoa(pageIndex))
		if page.InternalEmptyCookie {
			cookie = nil
		}
		control := InternalSearchBER(
			0xa0,
			InternalSearchBER(
				0x30,
				InternalSearchBER(4, []byte("1.2.840.113556.1.4.319")),
				InternalSearchBER(
					4,
					InternalSearchBER(0x30, []byte{2, 1, 0}, InternalSearchBER(4, cookie)),
				),
			),
		)
		if page.InternalOmitControl {
			control = nil
		}
		matched, diagnostic := []byte{}, []byte{}
		if page.InternalCode != 0 {
			matched = []byte("DC=example")
			diagnostic = []byte("private test diagnostic")
		}
		result := InternalSearchBER(
			0x65,
			[]byte{10, 1, page.InternalCode},
			InternalSearchBER(4, matched),
			InternalSearchBER(4, diagnostic),
		)
		if _, err := conn.Write(InternalSearchBER(0x30, messageID, result, control)); err != nil {
			return err
		}
	}
}

// SearchRequest places the BER filter after base, scope, derefAliases,
// sizeLimit, timeLimit and typesOnly. Retain the complete tagged filter so
// tests can verify WinLDAP's real string-to-BER translation.
func InternalSearchWireFilter(request []byte) ([]byte, error) {
	var err error
	for _, tag := range []byte{4, 10, 10, 2, 2, 1} {
		_, request, err = InternalTakeSearchBER(request, tag)
		if err != nil {
			return nil, err
		}
	}
	if len(request) == 0 {
		return nil, admodel.ErrInvalidResult
	}
	_, rest, err := InternalTakeSearchBER(request, request[0])
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), request[:len(request)-len(rest)]...), nil
}

func InternalSearchWirePageSize(encoded []byte) (int, error) {
	controls, _, err := InternalTakeSearchBER(encoded, 0xa0)
	if err != nil {
		return 0, err
	}
	control, _, err := InternalTakeSearchBER(controls, 0x30)
	if err != nil {
		return 0, err
	}
	_, rest, err := InternalTakeSearchBER(control, 4)
	if err != nil {
		return 0, err
	}
	if len(rest) > 0 && rest[0] == 1 {
		_, rest, err = InternalTakeSearchBER(rest, 1)
		if err != nil {
			return 0, err
		}
	}
	value, _, err := InternalTakeSearchBER(rest, 4)
	if err != nil {
		return 0, err
	}
	sequence, _, err := InternalTakeSearchBER(value, 0x30)
	if err != nil {
		return 0, err
	}
	number, _, err := InternalTakeSearchBER(sequence, 2)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, b := range number {
		n = n*256 + int(b)
	}
	return n, nil
}

func InternalSearchWireAttribute(name string, values ...[]byte) []byte {
	encoded := make([][]byte, len(values))
	for i, value := range values {
		encoded[i] = InternalSearchBER(4, value)
	}
	return InternalSearchBER(
		0x30,
		InternalSearchBER(4, []byte(name)),
		InternalSearchBER(0x31, encoded...),
	)
}

func InternalSearchBER(tag byte, values ...[]byte) []byte {
	n := 0
	for _, value := range values {
		n += len(value)
	}
	encoded := []byte{tag, byte(n)}
	if n >= 128 {
		encoded = []byte{tag, 0x82, byte(n >> 8), byte(n)}
	}
	for _, value := range values {
		encoded = append(encoded, value...)
	}
	return encoded
}

func InternalReadSearchBER(r io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	if header[0] != 0x30 {
		return nil, fmt.Errorf("unexpected LDAP envelope tag %x", header[0])
	}
	n := int(header[1])
	if n&128 != 0 {
		bytes := make([]byte, n&127)
		if len(bytes) > 4 {
			return nil, errors.New("excessive BER length")
		}
		if _, err := io.ReadFull(r, bytes); err != nil {
			return nil, err
		}
		n = 0
		for _, b := range bytes {
			n = n*256 + int(b)
		}
	}
	if n > 65536 {
		return nil, errors.New("excessive LDAP packet")
	}
	payload := make([]byte, n)
	_, err := io.ReadFull(r, payload)
	return payload, err
}

func InternalTakeSearchBER(encoded []byte, tag byte) ([]byte, []byte, error) {
	if len(encoded) < 2 || encoded[0] != tag {
		return nil, nil, fmt.Errorf("missing BER tag %x", tag)
	}
	n, offset := int(encoded[1]), 2
	if n&128 != 0 {
		count := n & 127
		if count == 0 || count > 4 || len(encoded) < offset+count {
			return nil, nil, errors.New("invalid BER length")
		}
		n = 0
		for _, b := range encoded[offset : offset+count] {
			n = n*256 + int(b)
		}
		offset += count
	}
	if n > len(encoded)-offset {
		return nil, nil, errors.New("truncated BER")
	}
	return encoded[offset : offset+n], encoded[offset+n:], nil
}

type InternalSearchNativeCounts struct{ InternalControls, InternalControlSets, InternalCookies, InternalMessages, InternalValues, InternalNames, InternalCursors int }

func InternalCountedSearchAPI(counts *InternalSearchNativeCounts) adengine.InternalLdapAPI {
	api := adengine.InternalSystemLDAPAPI()
	original := api
	api.InternalCreatePageControl = func(h *ldap.LDAP, n uint32, b *ldap.LDAP_BERVAL, critical byte, c **ldap.LDAPControlW) uint32 {
		status := original.InternalCreatePageControl(h, n, b, critical, c)
		if *c != nil {
			counts.InternalControls++
		}
		return status
	}
	api.InternalControlFree = func(c *ldap.LDAPControlW) uint32 { counts.InternalControls--; return original.InternalControlFree(c) }
	api.InternalControlsFree = func(c **ldap.LDAPControlW) uint32 {
		counts.InternalControlSets--
		return original.InternalControlsFree(c)
	}
	api.InternalParsePageControl = func(h *ldap.LDAP, c **ldap.LDAPControlW, n *uint32, b **ldap.LDAP_BERVAL) uint32 {
		status := original.InternalParsePageControl(h, c, n, b)
		if *b != nil {
			counts.InternalCookies++
		}
		return status
	}
	api.InternalCookieFree = func(b *ldap.LDAP_BERVAL) { counts.InternalCookies--; original.InternalCookieFree(b) }
	api.InternalResult = func(h *ldap.LDAP, id, all uint32, wait *ldap.LDAP_TIMEVAL, m **ldap.LDAPMessage) uint32 {
		kind := original.InternalResult(h, id, all, wait, m)
		if *m != nil {
			counts.InternalMessages++
		}
		return kind
	}
	api.InternalMessageFree = func(m *ldap.LDAPMessage) uint32 { counts.InternalMessages--; return original.InternalMessageFree(m) }
	api.InternalValues = func(h *ldap.LDAP, m *ldap.LDAPMessage, n string) **ldap.LDAP_BERVAL {
		v := original.InternalValues(h, m, n)
		if v != nil {
			counts.InternalValues++
		}
		return v
	}
	api.InternalValuesFree = func(v **ldap.LDAP_BERVAL) uint32 { counts.InternalValues--; return original.InternalValuesFree(v) }
	api.InternalGetDN = func(h *ldap.LDAP, m *ldap.LDAPMessage) foundation.PWSTR {
		v := original.InternalGetDN(h, m)
		if v != nil {
			counts.InternalNames++
		}
		return v
	}
	api.InternalFirstAttribute = func(h *ldap.LDAP, m *ldap.LDAPMessage, c **ldap.BerElement) foundation.PWSTR {
		v := original.InternalFirstAttribute(h, m, c)
		if v != nil {
			counts.InternalNames++
		}
		if *c != nil {
			counts.InternalCursors++
		}
		return v
	}
	api.InternalNextAttribute = func(h *ldap.LDAP, m *ldap.LDAPMessage, c *ldap.BerElement) foundation.PWSTR {
		v := original.InternalNextAttribute(h, m, c)
		if v != nil {
			counts.InternalNames++
		}
		return v
	}
	api.InternalMemoryFree = func(v foundation.PWSTR) { counts.InternalNames--; original.InternalMemoryFree(v) }
	api.InternalBerFree = func(c *ldap.BerElement, free int32) { counts.InternalCursors--; original.InternalBerFree(c, free) }
	api.InternalParseResult = func(h *ldap.LDAP, m *ldap.LDAPMessage, code *uint32, dn, diag *foundation.PWSTR, r ***uint16, c ***ldap.LDAPControlW, free foundation.BOOLEAN) uint32 {
		status := original.InternalParseResult(h, m, code, dn, diag, r, c, free)
		if c != nil && *c != nil {
			counts.InternalControlSets++
		}
		if *dn != nil {
			counts.InternalNames++
		}
		if *diag != nil {
			counts.InternalNames++
		}
		return status
	}
	return api
}

func InternalSearchWireClient(
	t *testing.T,
	f *InternalSearchWireFixture,
	api adengine.InternalLdapAPI,
) *adengine.Client {
	t.Helper()
	return InternalSearchWireClientWithTimeout(t, f, api, time.Second)
}

func InternalSearchWireClientWithTimeout(
	t *testing.T,
	f *InternalSearchWireFixture,
	api adengine.InternalLdapAPI,
	timeout time.Duration,
) *adengine.Client {
	t.Helper()
	handle := api.InternalInit("127.0.0.1", uint32(f.InternalListener.Addr().(*net.TCPAddr).Port))
	if handle == nil {
		t.Fatal("ldap_initW failed")
	}
	session := &adengine.InternalLdapSession{
		InternalHandle:  handle,
		InternalApi:     api,
		InternalTimeout: timeout,
	}
	for _, option := range []uint32{ldap.LDAP_OPT_AUTO_RECONNECT, ldap.LDAP_OPT_REFERRALS} {
		if err := session.InternalSetUint(option, 0); err != nil {
			_ = session.InternalClose()
			t.Fatal(err)
		}
	}
	version := uint32(ldap.LDAP_VERSION3)
	if status := api.InternalSetOption(
		handle,
		int32(ldap.LDAP_OPT_PROTOCOL_VERSION),
		unsafe.Pointer(&version),
	); status != 0 {
		_ = session.InternalClose()
		t.Fatal(status)
	}
	client := adengine.InternalNewClient(admodel.Config{Timeout: timeout}, session)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client
}

func TestNativePagedSearchWireResultsAndOwnership(t *testing.T) {
	for _, tc := range []struct {
		InternalName                string
		InternalPages               []InternalSearchWirePage
		InternalLimit, InternalWant int
		InternalComplete            bool
		InternalCode                uint32
		InternalRanged              bool
	}{
		{"zero", []InternalSearchWirePage{{InternalEmptyCookie: true}}, 0, 0, true, 0, false},
		{"one", []InternalSearchWirePage{{InternalCount: 1, InternalEmptyCookie: true}}, 0, 1, true, 0, false},
		{"many and empty intermediate", []InternalSearchWirePage{{InternalCount: 2}, {}, {InternalCount: 2}, {InternalCount: 1, InternalEmptyCookie: true}}, 0, 5, true, 0, false},
		{"limit in page", []InternalSearchWirePage{{InternalCount: 2}, {InternalCount: 1}}, 3, 3, false, 0, false},
		{"exact page limit", []InternalSearchWirePage{{InternalCount: 2}}, 2, 2, false, 0, false},
		{"missing base", []InternalSearchWirePage{{InternalCode: 32}}, 0, 0, false, 32, false},
		{"server size limit", []InternalSearchWirePage{{InternalCount: 1, InternalCode: 4}}, 0, 1, false, 4, false},
		{"server time limit", []InternalSearchWirePage{{InternalCount: 1, InternalCode: 3}}, 0, 1, false, 3, false},
		{"permission denied", []InternalSearchWirePage{{InternalCode: 50}}, 0, 0, false, 50, false},
		{"paging unsupported", []InternalSearchWirePage{{InternalCode: 12}}, 0, 0, false, 12, false},
		{"ranged attribute", []InternalSearchWirePage{{InternalCount: 1, InternalRanged: true, InternalEmptyCookie: true}}, 0, 1, false, 0, true},
	} {
		t.Run(tc.InternalName, func(t *testing.T) {
			f := InternalNewSearchWireFixture(t, tc.InternalPages)
			var counts InternalSearchNativeCounts
			client := InternalSearchWireClient(t, f, InternalCountedSearchAPI(&counts))
			result, err := client.Search(
				context.Background(),
				admodel.SearchOptions{
					Base:        "DC=example",
					Scope:       admodel.ScopeSubtree,
					PageSize:    2,
					ResultLimit: tc.InternalLimit,
					Properties:  []string{"name", "objectGUID", "description", "member"},
				},
			)
			if len(result.Objects) != tc.InternalWant || result.Complete != tc.InternalComplete {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if tc.InternalCode != 0 {
				var native *admodel.LDAPError
				if !InternalHasLDAPCode(err, tc.InternalCode) || !errors.As(err, &native) ||
					native.Diagnostic != "private test diagnostic" ||
					native.MatchedDN != "DC=example" {
					t.Fatalf("native details lost: %v %#v", err, native)
				}
			} else if tc.InternalRanged {
				if !errors.Is(err, admodel.ErrIncompleteResult) {
					t.Fatal(err)
				}
				if _, state := result.Objects[0].Attribute(
					"member",
				); state != admodel.AttributePartial {
					t.Fatal("range silently marked complete")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if counts != (InternalSearchNativeCounts{}) {
				t.Fatalf("unreleased native allocations: %+v", counts)
			}
			if len(result.Objects) > 0 && !tc.InternalRanged {
				values, state := result.Objects[0].Attribute("objectGUID")
				if state != admodel.AttributePresent ||
					!reflect.DeepEqual(values[0][:3], []byte{0, 255, 128}) {
					t.Fatal("binary copy lost")
				}
				if _, state := result.Objects[0].Attribute(
					"description",
				); state != admodel.AttributeAbsent {
					t.Fatal("absent selection lost")
				}
			}
			if tc.InternalLimit > 0 && !result.LimitReached {
				t.Fatal("caller limit was not reported")
			}
		})
	}
}

// Omission is not evidence of an unset directory value. The same wire omission
// means Absent when explicitly selected and Unloaded when not selected. Actual
// ACL enforcement is qualified separately with the owned ordinary-user fixture.
func TestNativePagedSearchUnreturnedPropertyStates(t *testing.T) {
	f := InternalNewSearchWireFixture(
		t,
		[]InternalSearchWirePage{
			{InternalCount: 1, InternalEmptyCookie: true},
			{InternalCount: 1, InternalEmptyCookie: true},
		},
	)
	var counts InternalSearchNativeCounts
	client := InternalSearchWireClient(t, f, InternalCountedSearchAPI(&counts))
	for _, selected := range []bool{true, false} {
		properties := []string{"objectGUID"}
		wantState := admodel.AttributeUnloaded
		if selected {
			properties = append(properties, "description")
			wantState = admodel.AttributeAbsent
		}
		result, err := client.Search(
			context.Background(),
			admodel.SearchOptions{Base: "DC=example", Properties: properties},
		)
		if err != nil || !result.Complete || len(result.Objects) != 1 {
			t.Fatalf("selected=%v: complete visible object missing: %v", selected, err)
		}
		object := result.Objects[0]
		guid, state := object.Attribute("objectGUID")
		if object.DistinguishedName == "" || state != admodel.AttributePresent || len(guid) != 1 ||
			!reflect.DeepEqual(guid[0][:3], []byte{0, 255, 128}) {
			t.Fatal("omitted property lost visible DN/binary identity")
		}
		if values, state := object.Attribute(
			"description",
		); len(values) != 0 ||
			state != wantState {
			t.Fatalf("selected=%v: state=%v values=%v", selected, state, values)
		}
		if counts != (InternalSearchNativeCounts{}) {
			t.Fatalf("unreleased native allocations: %+v", counts)
		}
	}
}

func TestNativePagedSearchCancellationAndCleanupFailure(t *testing.T) {
	for _, failCleanup := range []bool{false, true} {
		t.Run(fmt.Sprint(failCleanup), func(t *testing.T) {
			f := InternalNewSearchWireFixture(t, []InternalSearchWirePage{{InternalStall: true}})
			var counts InternalSearchNativeCounts
			api := InternalCountedSearchAPI(&counts)
			if failCleanup {
				abandon := api.InternalAbandon
				api.InternalAbandon = func(h *ldap.LDAP, id uint32) uint32 { _ = abandon(h, id); return 80 }
			}
			client := InternalSearchWireClient(t, f, api)
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			started := time.Now()
			_, err := client.Search(ctx, admodel.SearchOptions{Base: "DC=example"})
			if !errors.Is(err, context.DeadlineExceeded) ||
				!errors.Is(err, admodel.ErrIncompleteResult) ||
				time.Since(started) > time.Second {
				t.Fatalf("cancel latency=%s err=%v", time.Since(started), err)
			}
			if failCleanup && !InternalHasLDAPCode(err, 80) {
				t.Fatal("cleanup error lost")
			}
			if counts != (InternalSearchNativeCounts{}) {
				t.Fatalf("unreleased allocations: %+v", counts)
			}
		})
	}
}

func TestNativePagedSearchSubmissionFailureRetiresAfterFree(t *testing.T) {
	var order []string
	s := &adengine.InternalLdapSession{
		InternalHandle:  new(ldap.LDAP),
		InternalTimeout: time.Second,
		InternalApi: adengine.InternalLdapAPI{
			InternalSetOption: func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 },
			InternalCreatePageControl: func(_ *ldap.LDAP, _ uint32, _ *ldap.LDAP_BERVAL, _ byte, c **ldap.LDAPControlW) uint32 {
				*c = new(ldap.LDAPControlW)
				return 0
			},
			InternalSearch: func(*ldap.LDAP, *string, uint32, string, **uint16, uint32, **ldap.LDAPControlW, **ldap.LDAPControlW, uint32, uint32, *uint32) uint32 {
				return 81
			},
			InternalControlFree: func(*ldap.LDAPControlW) uint32 { order = append(order, "control"); return 0 },
			InternalUnbind:      func(*ldap.LDAP) uint32 { order = append(order, "unbind"); return 0 },
		},
	}
	p := &adengine.InternalLdapSearch{InternalSession: s, InternalAttributes: make([]*uint16, 1)}
	_, _, err := p.InternalNext(context.Background(), 2)
	if !InternalHasLDAPCode(err, 81) {
		t.Fatal(err)
	}
	if err := p.InternalClose(); err != nil {
		t.Fatal(err)
	}
	_ = p.InternalClose()
	if !reflect.DeepEqual(order, []string{"control", "unbind"}) || s.InternalHandle != nil {
		t.Fatalf("order=%v handle=%p", order, s.InternalHandle)
	}
}

func TestNativePagedSearchRepeatedCallsReleaseEveryAllocation(t *testing.T) {
	pages := make([]InternalSearchWirePage, 100)
	for i := range pages {
		pages[i] = InternalSearchWirePage{InternalCount: 1, InternalEmptyCookie: true}
	}
	f := InternalNewSearchWireFixture(t, pages)
	var counts InternalSearchNativeCounts
	client := InternalSearchWireClient(t, f, InternalCountedSearchAPI(&counts))
	for i := range pages {
		result, err := client.Search(
			context.Background(),
			admodel.SearchOptions{Base: "DC=example", PageSize: 2},
		)
		if err != nil || !result.Complete || len(result.Objects) != 1 ||
			counts != (InternalSearchNativeCounts{}) {
			t.Fatalf("iteration %d: result=%+v err=%v resources=%+v", i, result, err, counts)
		}
	}
}

func TestNativePagedSearchCleanupWaitIsBounded(t *testing.T) {
	f := InternalNewSearchWireFixture(t, []InternalSearchWirePage{{InternalCount: 1}})
	f.InternalMu.Lock()
	f.InternalStallCleanup = true
	f.InternalMu.Unlock()
	var counts InternalSearchNativeCounts
	client := InternalSearchWireClient(t, f, InternalCountedSearchAPI(&counts))
	started := time.Now()
	result, err := client.Search(
		context.Background(),
		admodel.SearchOptions{Base: "DC=example", PageSize: 1, ResultLimit: 1},
	)
	if !errors.Is(err, context.DeadlineExceeded) || !result.LimitReached ||
		len(result.Objects) != 1 ||
		time.Since(started) > time.Second {
		t.Fatalf("result=%+v err=%v elapsed=%s", result, err, time.Since(started))
	}
	if counts != (InternalSearchNativeCounts{}) {
		t.Fatalf("unreleased allocations: %+v", counts)
	}
	if _, err := client.Search(
		context.Background(),
		admodel.SearchOptions{Base: "DC=example"},
	); !errors.Is(
		err,
		admodel.ErrClosed,
	) {
		t.Fatalf("uncertain cursor left session usable: %v", err)
	}
}

func TestNativePagedSearchPreservesCleanupFailures(t *testing.T) {
	for _, failure := range []string{"request-control", "response-controls", "message"} {
		t.Run(failure, func(t *testing.T) {
			f := InternalNewSearchWireFixture(
				t,
				[]InternalSearchWirePage{{InternalCount: 1, InternalEmptyCookie: true}},
			)
			var counts InternalSearchNativeCounts
			api := InternalCountedSearchAPI(&counts)
			switch failure {
			case "request-control":
				// Injected control-release failure immediately abandons/unbinds
				// the submitted request without reading the responder's writes.
				f.InternalAllowAbortedClose = true
				free := api.InternalControlFree
				api.InternalControlFree = func(c *ldap.LDAPControlW) uint32 { _ = free(c); return 80 }
			case "response-controls":
				free := api.InternalControlsFree
				api.InternalControlsFree = func(c **ldap.LDAPControlW) uint32 { _ = free(c); return 80 }
			case "message":
				free := api.InternalMessageFree
				api.InternalMessageFree = func(m *ldap.LDAPMessage) uint32 { _ = free(m); return 80 }
			}
			client := InternalSearchWireClient(t, f, api)
			result, err := client.Search(
				context.Background(),
				admodel.SearchOptions{Base: "DC=example"},
			)
			if !InternalHasLDAPCode(err, 80) || !errors.Is(err, admodel.ErrIncompleteResult) ||
				result.Complete {
				t.Fatalf("%+v %v", result, err)
			}
			if counts != (InternalSearchNativeCounts{}) {
				t.Fatalf("unreleased allocations: %+v", counts)
			}
			if failure == "request-control" {
				if _, err := client.Search(
					context.Background(),
					admodel.SearchOptions{Base: "DC=example"},
				); !errors.Is(
					err,
					admodel.ErrClosed,
				) {
					t.Fatalf("uncertain request retained its session: %v", err)
				}
			}
		})
	}
}

func TestNativeSearchParserOutputOwnershipAndMalformedDiagnostics(t *testing.T) {
	for _, failure := range []string{"parser failure", "malformed UTF-16", "unterminated UTF-16"} {
		t.Run(failure, func(t *testing.T) {
			units := []uint16{0xd800, 0}
			if failure == "unterminated UTF-16" {
				units = make([]uint16, 4096)
				for i := range units {
					units[i] = 'x'
				}
			}
			controls := []*ldap.LDAPControlW{new(ldap.LDAPControlW), nil}
			freedNames, freedControls, freedMessages, freedCookies := 0, 0, 0, 0
			s := &adengine.InternalLdapSession{
				InternalHandle: new(ldap.LDAP),
				InternalApi: adengine.InternalLdapAPI{
					InternalParseResult: func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, _ *foundation.PWSTR, diagnostic *foundation.PWSTR, _ ***uint16, out ***ldap.LDAPControlW, _ foundation.BOOLEAN) uint32 {
						*code = 3
						*diagnostic = &units[0]
						*out = &controls[0]
						if failure == "parser failure" {
							return 84
						}
						return 0
					},
					InternalMemoryFree:   func(foundation.PWSTR) { freedNames++ },
					InternalControlsFree: func(**ldap.LDAPControlW) uint32 { freedControls++; return 0 },
					InternalMessageFree:  func(*ldap.LDAPMessage) uint32 { freedMessages++; return 0 },
					InternalParsePageControl: func(_ *ldap.LDAP, _ **ldap.LDAPControlW, _ *uint32, out **ldap.LDAP_BERVAL) uint32 {
						if failure == "parser failure" {
							t.Fatal("read controls from failed parser")
						}
						*out = new(ldap.LDAP_BERVAL)
						return 0
					},
					InternalCookieFree:      func(*ldap.LDAP_BERVAL) { freedCookies++ },
					InternalCountReferences: func(*ldap.LDAP, *ldap.LDAPMessage) uint32 { return 0 },
					InternalCountEntries:    func(*ldap.LDAP, *ldap.LDAPMessage) uint32 { return 0 },
					InternalFirstEntry:      func(*ldap.LDAP, *ldap.LDAPMessage) *ldap.LDAPMessage { return nil },
					InternalUnbind:          func(*ldap.LDAP) uint32 { return 0 },
				},
			}
			p := &adengine.InternalLdapSearch{InternalSession: s}
			_, parsed, _, err := p.InternalReadPage(new(ldap.LDAPMessage))
			_ = p.InternalClose()
			if failure == "parser failure" {
				if !InternalHasLDAPCode(err, 84) || parsed ||
					errors.Is(err, admodel.ErrInvalidResult) ||
					freedCookies != 0 {
					t.Fatalf("failed parser output was decoded: %v", err)
				}
			} else if !InternalHasLDAPCode(err, 3) || !errors.Is(err, admodel.ErrInvalidResult) || !parsed || freedCookies != 1 {
				t.Fatalf("diagnostic error replaced original status: %v", err)
			}
			if freedNames != 1 || freedControls != 1 || freedMessages != 1 {
				t.Fatalf(
					"frees names=%d controls=%d messages=%d",
					freedNames,
					freedControls,
					freedMessages,
				)
			}
		})
	}
}

func TestNativePagedSearchRejectsTruncationAndCopiesFailureMessages(t *testing.T) {
	for _, failure := range []string{"missing control", "reference", "result failure"} {
		t.Run(failure, func(t *testing.T) {
			page := InternalSearchWirePage{
				InternalCount:       1,
				InternalEmptyCookie: true,
				InternalOmitControl: failure == "missing control",
				InternalReference:   failure == "reference",
			}
			f := InternalNewSearchWireFixture(t, []InternalSearchWirePage{page})
			var counts InternalSearchNativeCounts
			api := InternalCountedSearchAPI(&counts)
			if failure == "result failure" {
				original := api.InternalResult
				api.InternalResult = func(h *ldap.LDAP, id, all uint32, wait *ldap.LDAP_TIMEVAL, m **ldap.LDAPMessage) uint32 {
					kind := original(h, id, all, wait, m)
					if *m != nil {
						return ^uint32(0)
					}
					return kind
				}
			}
			client := InternalSearchWireClient(t, f, api)
			result, err := client.Search(
				context.Background(),
				admodel.SearchOptions{Base: "DC=example"},
			)
			if !errors.Is(err, admodel.ErrIncompleteResult) || result.Complete ||
				len(result.Objects) != 1 {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if counts != (InternalSearchNativeCounts{}) {
				t.Fatalf("unreleased allocations: %+v", counts)
			}
		})
	}
}

func TestNativeSearchCancellationAfterCompletedPage(t *testing.T) {
	f := InternalNewSearchWireFixture(t, []InternalSearchWirePage{{InternalCount: 1}})
	var counts InternalSearchNativeCounts
	api := InternalCountedSearchAPI(&counts)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	original := api.InternalResult
	api.InternalResult = func(h *ldap.LDAP, id, all uint32, wait *ldap.LDAP_TIMEVAL, m **ldap.LDAPMessage) uint32 {
		kind := original(h, id, all, wait, m)
		if *m != nil {
			cancel()
		}
		return kind
	}
	client := InternalSearchWireClient(t, f, api)
	result, err := client.Search(ctx, admodel.SearchOptions{Base: "DC=example"})
	if !errors.Is(err, context.Canceled) || len(result.Objects) != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	f.InternalMu.Lock()
	sizes := append([]int(nil), f.InternalSizes...)
	f.InternalMu.Unlock()
	if !reflect.DeepEqual(sizes, []int{256, 0}) || counts != (InternalSearchNativeCounts{}) {
		t.Fatalf("requests=%v resources=%+v", sizes, counts)
	}
}

func TestNativeSearchTerminalErrorWithoutControlKeepsSessionUsable(t *testing.T) {
	for _, code := range []byte{32, 3, 4, 50, 12} {
		t.Run(strconv.Itoa(int(code)), func(t *testing.T) {
			f := InternalNewSearchWireFixture(
				t,
				[]InternalSearchWirePage{
					{InternalCode: code, InternalOmitControl: true},
					{InternalCount: 1, InternalEmptyCookie: true},
				},
			)
			var counts InternalSearchNativeCounts
			client := InternalSearchWireClient(t, f, InternalCountedSearchAPI(&counts))
			_, err := client.Search(
				context.Background(),
				admodel.SearchOptions{Base: "CN=missing,DC=example"},
			)
			if !InternalHasLDAPCode(err, uint32(code)) {
				t.Fatal(err)
			}
			result, err := client.Search(
				context.Background(),
				admodel.SearchOptions{Base: "DC=example"},
			)
			if err != nil || !result.Complete || len(result.Objects) != 1 ||
				counts != (InternalSearchNativeCounts{}) {
				t.Fatalf("result=%+v err=%v resources=%+v", result, err, counts)
			}
		})
	}
}

func TestNativeAttributeNamesUseBoundedStrictDecoding(t *testing.T) {
	for _, unterminated := range []bool{false, true} {
		t.Run(fmt.Sprint(unterminated), func(t *testing.T) {
			units := []uint16{0xd800, 0}
			if unterminated {
				units = make([]uint16, 4096)
				for i := range units {
					units[i] = 'x'
				}
			}
			names, cursors := 0, 0
			s := &adengine.InternalLdapSession{
				InternalHandle: new(ldap.LDAP),
				InternalApi: adengine.InternalLdapAPI{
					InternalFirstAttribute: func(_ *ldap.LDAP, _ *ldap.LDAPMessage, c **ldap.BerElement) foundation.PWSTR {
						*c = new(ldap.BerElement)
						return &units[0]
					},
					InternalMemoryFree: func(foundation.PWSTR) { names++ },
					InternalBerFree:    func(*ldap.BerElement, int32) { cursors++ },
				},
			}
			_, err := s.InternalReadRawAttributes(new(ldap.LDAPMessage), true)
			if !errors.Is(err, admodel.ErrInvalidResult) || names != 1 || cursors != 1 {
				t.Fatalf("err=%v names=%d cursors=%d", err, names, cursors)
			}
		})
	}
}

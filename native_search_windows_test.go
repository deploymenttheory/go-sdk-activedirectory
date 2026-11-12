//go:build windows && (amd64 || arm64)

package activedirectory

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
)

// The loopback responder controls wire-level page boundaries and error results.
// The SDK uses real WinLDAP allocation, parsing, copying, polling and cleanup.
// Authentication is intentionally outside this fixture and covered by AD labs.
type searchWirePage struct {
	count       int
	code        byte
	emptyCookie bool
	stall       bool
	ranged      bool
	omitControl bool
	reference   bool
}
type searchWireFixture struct {
	listener     net.Listener
	mu           sync.Mutex
	conn         net.Conn
	sizes        []int
	pages        []searchWirePage
	done         chan error
	stallCleanup bool
}

func newSearchWireFixture(t *testing.T, pages []searchWirePage) *searchWireFixture {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &searchWireFixture{listener: listener, pages: pages, done: make(chan error, 1)}
	go func() { f.done <- f.serve() }()
	t.Cleanup(func() {
		_ = listener.Close()
		f.mu.Lock()
		if f.conn != nil {
			_ = f.conn.Close()
		}
		f.mu.Unlock()
		select {
		case err := <-f.done:
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, syscall.WSAECONNRESET) {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("loopback LDAP responder did not stop")
		}
	})
	return f
}

func (f *searchWireFixture) serve() error {
	conn, err := f.listener.Accept()
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.conn = conn
	f.mu.Unlock()
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	pageIndex := 0
	for {
		packet, err := readSearchBER(conn)
		if err != nil {
			return err
		}
		id, rest, err := takeSearchBER(packet, 2)
		if err != nil || len(rest) < 2 {
			return fmt.Errorf("invalid LDAP envelope: %v", err)
		}
		if rest[0] == 0x42 {
			return nil
		} // unbind
		if rest[0] == 0x50 {
			continue
		} // abandon
		request, controls, err := takeSearchBER(rest, 0x63)
		if err != nil {
			return err
		}
		base, _, err := takeSearchBER(request, 4)
		if err != nil {
			return err
		}
		messageID := searchBER(2, id)
		if len(base) == 0 {
			entry := searchBER(0x64, searchBER(4, nil), searchBER(0x30, searchWireAttribute("supportedControl", []byte("1.2.840.113556.1.4.319"))))
			if _, err := conn.Write(searchBER(0x30, messageID, entry)); err != nil {
				return err
			}
			if _, err := conn.Write(searchBER(0x30, messageID, searchBER(0x65, []byte{10, 1, 0, 4, 0, 4, 0}))); err != nil {
				return err
			}
			continue
		}
		size, err := searchWirePageSize(controls)
		if err != nil {
			return err
		}
		f.mu.Lock()
		f.sizes = append(f.sizes, size)
		f.mu.Unlock()
		if size == 0 {
			f.mu.Lock()
			stallCleanup := f.stallCleanup
			f.mu.Unlock()
			if !stallCleanup {
				control := searchBER(0xa0, searchBER(0x30, searchBER(4, []byte("1.2.840.113556.1.4.319")), searchBER(4, searchBER(0x30, []byte{2, 1, 0, 4, 0}))))
				if _, err := conn.Write(searchBER(0x30, messageID, searchBER(0x65, []byte{10, 1, 0, 4, 0, 4, 0}), control)); err != nil {
					return err
				}
			}
			continue
		} // release server cookie
		if pageIndex >= len(f.pages) {
			return fmt.Errorf("unexpected page request %d", pageIndex)
		}
		page := f.pages[pageIndex]
		pageIndex++
		if page.stall {
			continue
		}
		if page.reference {
			if _, err := conn.Write(searchBER(0x30, messageID, searchBER(0x73, searchBER(4, []byte("ldap://other.invalid/DC=else"))))); err != nil {
				return err
			}
		}
		for i := 0; i < page.count; i++ {
			attrs := searchBER(0x30, searchWireAttribute("objectGUID", []byte{0, 255, 128, byte(pageIndex), byte(i)}), searchWireAttribute("name", []byte(fmt.Sprintf("object-%d-%d", pageIndex, i))))
			if page.ranged {
				attrs = searchBER(0x30, searchWireAttribute("member;range=0-1499", []byte("CN=first,DC=example")))
			}
			entry := searchBER(0x64, searchBER(4, []byte(fmt.Sprintf("CN=object-%d-%d,DC=example", pageIndex, i))), attrs)
			if _, err := conn.Write(searchBER(0x30, messageID, entry)); err != nil {
				return err
			}
		}
		cookie := []byte(strconv.Itoa(pageIndex))
		if page.emptyCookie {
			cookie = nil
		}
		control := searchBER(0xa0, searchBER(0x30, searchBER(4, []byte("1.2.840.113556.1.4.319")), searchBER(4, searchBER(0x30, []byte{2, 1, 0}, searchBER(4, cookie)))))
		if page.omitControl {
			control = nil
		}
		matched, diagnostic := []byte{}, []byte{}
		if page.code != 0 {
			matched = []byte("DC=example")
			diagnostic = []byte("private test diagnostic")
		}
		result := searchBER(0x65, []byte{10, 1, page.code}, searchBER(4, matched), searchBER(4, diagnostic))
		if _, err := conn.Write(searchBER(0x30, messageID, result, control)); err != nil {
			return err
		}
	}
}

func searchWirePageSize(encoded []byte) (int, error) {
	controls, _, err := takeSearchBER(encoded, 0xa0)
	if err != nil {
		return 0, err
	}
	control, _, err := takeSearchBER(controls, 0x30)
	if err != nil {
		return 0, err
	}
	_, rest, err := takeSearchBER(control, 4)
	if err != nil {
		return 0, err
	}
	if len(rest) > 0 && rest[0] == 1 {
		_, rest, err = takeSearchBER(rest, 1)
		if err != nil {
			return 0, err
		}
	}
	value, _, err := takeSearchBER(rest, 4)
	if err != nil {
		return 0, err
	}
	sequence, _, err := takeSearchBER(value, 0x30)
	if err != nil {
		return 0, err
	}
	number, _, err := takeSearchBER(sequence, 2)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, b := range number {
		n = n*256 + int(b)
	}
	return n, nil
}

func searchWireAttribute(name string, value []byte) []byte {
	return searchBER(0x30, searchBER(4, []byte(name)), searchBER(0x31, searchBER(4, value)))
}
func searchBER(tag byte, values ...[]byte) []byte {
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
func readSearchBER(r io.Reader) ([]byte, error) {
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
func takeSearchBER(encoded []byte, tag byte) ([]byte, []byte, error) {
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

type searchNativeCounts struct{ controls, controlSets, cookies, messages, values, names, cursors int }

func countedSearchAPI(counts *searchNativeCounts) ldapAPI {
	api := systemLDAPAPI()
	original := api
	api.createPageControl = func(h *ldap.LDAP, n uint32, b *ldap.LDAP_BERVAL, critical byte, c **ldap.LDAPControlW) uint32 {
		status := original.createPageControl(h, n, b, critical, c)
		if *c != nil {
			counts.controls++
		}
		return status
	}
	api.controlFree = func(c *ldap.LDAPControlW) uint32 { counts.controls--; return original.controlFree(c) }
	api.controlsFree = func(c **ldap.LDAPControlW) uint32 { counts.controlSets--; return original.controlsFree(c) }
	api.parsePageControl = func(h *ldap.LDAP, c **ldap.LDAPControlW, n *uint32, b **ldap.LDAP_BERVAL) uint32 {
		status := original.parsePageControl(h, c, n, b)
		if *b != nil {
			counts.cookies++
		}
		return status
	}
	api.cookieFree = func(b *ldap.LDAP_BERVAL) { counts.cookies--; original.cookieFree(b) }
	api.result = func(h *ldap.LDAP, id, all uint32, wait *ldap.LDAP_TIMEVAL, m **ldap.LDAPMessage) uint32 {
		kind := original.result(h, id, all, wait, m)
		if *m != nil {
			counts.messages++
		}
		return kind
	}
	api.messageFree = func(m *ldap.LDAPMessage) uint32 { counts.messages--; return original.messageFree(m) }
	api.values = func(h *ldap.LDAP, m *ldap.LDAPMessage, n string) **ldap.LDAP_BERVAL {
		v := original.values(h, m, n)
		if v != nil {
			counts.values++
		}
		return v
	}
	api.valuesFree = func(v **ldap.LDAP_BERVAL) uint32 { counts.values--; return original.valuesFree(v) }
	api.getDN = func(h *ldap.LDAP, m *ldap.LDAPMessage) foundation.PWSTR {
		v := original.getDN(h, m)
		if v != nil {
			counts.names++
		}
		return v
	}
	api.firstAttribute = func(h *ldap.LDAP, m *ldap.LDAPMessage, c **ldap.BerElement) foundation.PWSTR {
		v := original.firstAttribute(h, m, c)
		if v != nil {
			counts.names++
		}
		if *c != nil {
			counts.cursors++
		}
		return v
	}
	api.nextAttribute = func(h *ldap.LDAP, m *ldap.LDAPMessage, c *ldap.BerElement) foundation.PWSTR {
		v := original.nextAttribute(h, m, c)
		if v != nil {
			counts.names++
		}
		return v
	}
	api.memoryFree = func(v foundation.PWSTR) { counts.names--; original.memoryFree(v) }
	api.berFree = func(c *ldap.BerElement, free int32) { counts.cursors--; original.berFree(c, free) }
	api.parseResult = func(h *ldap.LDAP, m *ldap.LDAPMessage, code *uint32, dn, diag *foundation.PWSTR, r ***uint16, c ***ldap.LDAPControlW, free foundation.BOOLEAN) uint32 {
		status := original.parseResult(h, m, code, dn, diag, r, c, free)
		if c != nil && *c != nil {
			counts.controlSets++
		}
		if *dn != nil {
			counts.names++
		}
		if *diag != nil {
			counts.names++
		}
		return status
	}
	return api
}

func searchWireClient(t *testing.T, f *searchWireFixture, api ldapAPI) *Client {
	t.Helper()
	handle := api.init("127.0.0.1", uint32(f.listener.Addr().(*net.TCPAddr).Port))
	if handle == nil {
		t.Fatal("ldap_initW failed")
	}
	session := &ldapSession{handle: handle, api: api, timeout: time.Second}
	for _, option := range []uint32{ldap.LDAP_OPT_AUTO_RECONNECT, ldap.LDAP_OPT_REFERRALS} {
		if err := session.setUint(option, 0); err != nil {
			_ = session.close()
			t.Fatal(err)
		}
	}
	version := uint32(ldap.LDAP_VERSION3)
	if status := api.setOption(handle, int32(ldap.LDAP_OPT_PROTOCOL_VERSION), unsafe.Pointer(&version)); status != 0 {
		_ = session.close()
		t.Fatal(status)
	}
	client := newClient(Config{Timeout: time.Second}, session)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client
}

func TestNativePagedSearchWireResultsAndOwnership(t *testing.T) {
	for _, tc := range []struct {
		name        string
		pages       []searchWirePage
		limit, want int
		complete    bool
		code        uint32
		ranged      bool
	}{
		{"zero", []searchWirePage{{emptyCookie: true}}, 0, 0, true, 0, false},
		{"one", []searchWirePage{{count: 1, emptyCookie: true}}, 0, 1, true, 0, false},
		{"many and empty intermediate", []searchWirePage{{count: 2}, {}, {count: 2}, {count: 1, emptyCookie: true}}, 0, 5, true, 0, false},
		{"limit in page", []searchWirePage{{count: 2}, {count: 1}}, 3, 3, false, 0, false},
		{"exact page limit", []searchWirePage{{count: 2}}, 2, 2, false, 0, false},
		{"missing base", []searchWirePage{{code: 32}}, 0, 0, false, 32, false},
		{"server size limit", []searchWirePage{{count: 1, code: 4}}, 0, 1, false, 4, false},
		{"server time limit", []searchWirePage{{count: 1, code: 3}}, 0, 1, false, 3, false},
		{"permission denied", []searchWirePage{{code: 50}}, 0, 0, false, 50, false},
		{"paging unsupported", []searchWirePage{{code: 12}}, 0, 0, false, 12, false},
		{"ranged attribute", []searchWirePage{{count: 1, ranged: true, emptyCookie: true}}, 0, 1, false, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSearchWireFixture(t, tc.pages)
			var counts searchNativeCounts
			client := searchWireClient(t, f, countedSearchAPI(&counts))
			result, err := client.Search(context.Background(), SearchOptions{Base: "DC=example", Scope: ScopeSubtree, PageSize: 2, ResultLimit: tc.limit, Properties: []string{"name", "objectGUID", "description", "member"}})
			if len(result.Objects) != tc.want || result.Complete != tc.complete {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if tc.code != 0 {
				var native *LDAPError
				if !hasLDAPCode(err, tc.code) || !errors.As(err, &native) || native.Diagnostic != "private test diagnostic" || native.MatchedDN != "DC=example" {
					t.Fatalf("native details lost: %v %#v", err, native)
				}
			} else if tc.ranged {
				if !errors.Is(err, ErrIncompleteResult) {
					t.Fatal(err)
				}
				if _, state := result.Objects[0].Attribute("member"); state != AttributePartial {
					t.Fatal("range silently marked complete")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if counts != (searchNativeCounts{}) {
				t.Fatalf("unreleased native allocations: %+v", counts)
			}
			if len(result.Objects) > 0 && !tc.ranged {
				values, state := result.Objects[0].Attribute("objectGUID")
				if state != AttributePresent || !reflect.DeepEqual(values[0][:3], []byte{0, 255, 128}) {
					t.Fatal("binary copy lost")
				}
				if _, state := result.Objects[0].Attribute("description"); state != AttributeAbsent {
					t.Fatal("absent selection lost")
				}
			}
			if tc.limit > 0 && !result.LimitReached {
				t.Fatal("caller limit was not reported")
			}
		})
	}
}

func TestNativePagedSearchCancellationAndCleanupFailure(t *testing.T) {
	for _, failCleanup := range []bool{false, true} {
		t.Run(fmt.Sprint(failCleanup), func(t *testing.T) {
			f := newSearchWireFixture(t, []searchWirePage{{stall: true}})
			var counts searchNativeCounts
			api := countedSearchAPI(&counts)
			if failCleanup {
				abandon := api.abandon
				api.abandon = func(h *ldap.LDAP, id uint32) uint32 { _ = abandon(h, id); return 80 }
			}
			client := searchWireClient(t, f, api)
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			started := time.Now()
			_, err := client.Search(ctx, SearchOptions{Base: "DC=example"})
			if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrIncompleteResult) || time.Since(started) > time.Second {
				t.Fatalf("cancel latency=%s err=%v", time.Since(started), err)
			}
			if failCleanup && !hasLDAPCode(err, 80) {
				t.Fatal("cleanup error lost")
			}
			if counts != (searchNativeCounts{}) {
				t.Fatalf("unreleased allocations: %+v", counts)
			}
		})
	}
}

func TestNativePagedSearchSubmissionFailureRetiresAfterFree(t *testing.T) {
	var order []string
	s := &ldapSession{handle: new(ldap.LDAP), timeout: time.Second, api: ldapAPI{
		setOption: func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 },
		createPageControl: func(_ *ldap.LDAP, _ uint32, _ *ldap.LDAP_BERVAL, _ byte, c **ldap.LDAPControlW) uint32 {
			*c = new(ldap.LDAPControlW)
			return 0
		},
		search: func(*ldap.LDAP, *string, uint32, string, **uint16, uint32, **ldap.LDAPControlW, **ldap.LDAPControlW, uint32, uint32, *uint32) uint32 {
			return 81
		},
		controlFree: func(*ldap.LDAPControlW) uint32 { order = append(order, "control"); return 0 },
		unbind:      func(*ldap.LDAP) uint32 { order = append(order, "unbind"); return 0 },
	}}
	p := &ldapSearch{session: s, attributes: make([]*uint16, 1)}
	_, _, err := p.next(context.Background(), 2)
	if !hasLDAPCode(err, 81) {
		t.Fatal(err)
	}
	if err := p.close(); err != nil {
		t.Fatal(err)
	}
	_ = p.close()
	if !reflect.DeepEqual(order, []string{"control", "unbind"}) || s.handle != nil {
		t.Fatalf("order=%v handle=%p", order, s.handle)
	}
}

func TestNativePagedSearchRepeatedCallsReleaseEveryAllocation(t *testing.T) {
	pages := make([]searchWirePage, 100)
	for i := range pages {
		pages[i] = searchWirePage{count: 1, emptyCookie: true}
	}
	f := newSearchWireFixture(t, pages)
	var counts searchNativeCounts
	client := searchWireClient(t, f, countedSearchAPI(&counts))
	for i := range pages {
		result, err := client.Search(context.Background(), SearchOptions{Base: "DC=example", PageSize: 2})
		if err != nil || !result.Complete || len(result.Objects) != 1 || counts != (searchNativeCounts{}) {
			t.Fatalf("iteration %d: result=%+v err=%v resources=%+v", i, result, err, counts)
		}
	}
}

func TestNativePagedSearchCleanupWaitIsBounded(t *testing.T) {
	f := newSearchWireFixture(t, []searchWirePage{{count: 1}})
	f.mu.Lock()
	f.stallCleanup = true
	f.mu.Unlock()
	var counts searchNativeCounts
	client := searchWireClient(t, f, countedSearchAPI(&counts))
	started := time.Now()
	result, err := client.Search(context.Background(), SearchOptions{Base: "DC=example", PageSize: 1, ResultLimit: 1})
	if !errors.Is(err, context.DeadlineExceeded) || !result.LimitReached || len(result.Objects) != 1 || time.Since(started) > time.Second {
		t.Fatalf("result=%+v err=%v elapsed=%s", result, err, time.Since(started))
	}
	if counts != (searchNativeCounts{}) {
		t.Fatalf("unreleased allocations: %+v", counts)
	}
	if _, err := client.Search(context.Background(), SearchOptions{Base: "DC=example"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("uncertain cursor left session usable: %v", err)
	}
}

func TestNativePagedSearchPreservesCleanupFailures(t *testing.T) {
	for _, failure := range []string{"request-control", "response-controls", "message"} {
		t.Run(failure, func(t *testing.T) {
			f := newSearchWireFixture(t, []searchWirePage{{count: 1, emptyCookie: true}})
			var counts searchNativeCounts
			api := countedSearchAPI(&counts)
			switch failure {
			case "request-control":
				free := api.controlFree
				api.controlFree = func(c *ldap.LDAPControlW) uint32 { _ = free(c); return 80 }
			case "response-controls":
				free := api.controlsFree
				api.controlsFree = func(c **ldap.LDAPControlW) uint32 { _ = free(c); return 80 }
			case "message":
				free := api.messageFree
				api.messageFree = func(m *ldap.LDAPMessage) uint32 { _ = free(m); return 80 }
			}
			client := searchWireClient(t, f, api)
			result, err := client.Search(context.Background(), SearchOptions{Base: "DC=example"})
			if !hasLDAPCode(err, 80) || !errors.Is(err, ErrIncompleteResult) || result.Complete {
				t.Fatalf("%+v %v", result, err)
			}
			if counts != (searchNativeCounts{}) {
				t.Fatalf("unreleased allocations: %+v", counts)
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
			s := &ldapSession{handle: new(ldap.LDAP), api: ldapAPI{
				parseResult: func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, _ *foundation.PWSTR, diagnostic *foundation.PWSTR, _ ***uint16, out ***ldap.LDAPControlW, _ foundation.BOOLEAN) uint32 {
					*code = 3
					*diagnostic = &units[0]
					*out = &controls[0]
					if failure == "parser failure" {
						return 84
					}
					return 0
				},
				memoryFree: func(foundation.PWSTR) { freedNames++ }, controlsFree: func(**ldap.LDAPControlW) uint32 { freedControls++; return 0 }, messageFree: func(*ldap.LDAPMessage) uint32 { freedMessages++; return 0 },
				parsePageControl: func(_ *ldap.LDAP, _ **ldap.LDAPControlW, _ *uint32, out **ldap.LDAP_BERVAL) uint32 {
					if failure == "parser failure" {
						t.Fatal("read controls from failed parser")
					}
					*out = new(ldap.LDAP_BERVAL)
					return 0
				},
				cookieFree: func(*ldap.LDAP_BERVAL) { freedCookies++ }, countReferences: func(*ldap.LDAP, *ldap.LDAPMessage) uint32 { return 0 }, countEntries: func(*ldap.LDAP, *ldap.LDAPMessage) uint32 { return 0 }, firstEntry: func(*ldap.LDAP, *ldap.LDAPMessage) *ldap.LDAPMessage { return nil },
				unbind: func(*ldap.LDAP) uint32 { return 0 },
			}}
			p := &ldapSearch{session: s}
			_, parsed, _, err := p.readPage(new(ldap.LDAPMessage))
			_ = p.close()
			if failure == "parser failure" {
				if !hasLDAPCode(err, 84) || parsed || errors.Is(err, ErrInvalidResult) || freedCookies != 0 {
					t.Fatalf("failed parser output was decoded: %v", err)
				}
			} else if !hasLDAPCode(err, 3) || !errors.Is(err, ErrInvalidResult) || !parsed || freedCookies != 1 {
				t.Fatalf("diagnostic error replaced original status: %v", err)
			}
			if freedNames != 1 || freedControls != 1 || freedMessages != 1 {
				t.Fatalf("frees names=%d controls=%d messages=%d", freedNames, freedControls, freedMessages)
			}
		})
	}
}

func TestNativePagedSearchRejectsTruncationAndCopiesFailureMessages(t *testing.T) {
	for _, failure := range []string{"missing control", "reference", "result failure"} {
		t.Run(failure, func(t *testing.T) {
			page := searchWirePage{count: 1, emptyCookie: true, omitControl: failure == "missing control", reference: failure == "reference"}
			f := newSearchWireFixture(t, []searchWirePage{page})
			var counts searchNativeCounts
			api := countedSearchAPI(&counts)
			if failure == "result failure" {
				original := api.result
				api.result = func(h *ldap.LDAP, id, all uint32, wait *ldap.LDAP_TIMEVAL, m **ldap.LDAPMessage) uint32 {
					kind := original(h, id, all, wait, m)
					if *m != nil {
						return ^uint32(0)
					}
					return kind
				}
			}
			client := searchWireClient(t, f, api)
			result, err := client.Search(context.Background(), SearchOptions{Base: "DC=example"})
			if !errors.Is(err, ErrIncompleteResult) || result.Complete || len(result.Objects) != 1 {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if counts != (searchNativeCounts{}) {
				t.Fatalf("unreleased allocations: %+v", counts)
			}
		})
	}
}

func TestNativeSearchCancellationAfterCompletedPage(t *testing.T) {
	f := newSearchWireFixture(t, []searchWirePage{{count: 1}})
	var counts searchNativeCounts
	api := countedSearchAPI(&counts)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	original := api.result
	api.result = func(h *ldap.LDAP, id, all uint32, wait *ldap.LDAP_TIMEVAL, m **ldap.LDAPMessage) uint32 {
		kind := original(h, id, all, wait, m)
		if *m != nil {
			cancel()
		}
		return kind
	}
	client := searchWireClient(t, f, api)
	result, err := client.Search(ctx, SearchOptions{Base: "DC=example"})
	if !errors.Is(err, context.Canceled) || len(result.Objects) != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	f.mu.Lock()
	sizes := append([]int(nil), f.sizes...)
	f.mu.Unlock()
	if !reflect.DeepEqual(sizes, []int{256, 0}) || counts != (searchNativeCounts{}) {
		t.Fatalf("requests=%v resources=%+v", sizes, counts)
	}
}

func TestNativeSearchTerminalErrorWithoutControlKeepsSessionUsable(t *testing.T) {
	for _, code := range []byte{32, 3, 4, 50, 12} {
		t.Run(strconv.Itoa(int(code)), func(t *testing.T) {
			f := newSearchWireFixture(t, []searchWirePage{{code: code, omitControl: true}, {count: 1, emptyCookie: true}})
			var counts searchNativeCounts
			client := searchWireClient(t, f, countedSearchAPI(&counts))
			_, err := client.Search(context.Background(), SearchOptions{Base: "CN=missing,DC=example"})
			if !hasLDAPCode(err, uint32(code)) {
				t.Fatal(err)
			}
			result, err := client.Search(context.Background(), SearchOptions{Base: "DC=example"})
			if err != nil || !result.Complete || len(result.Objects) != 1 || counts != (searchNativeCounts{}) {
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
			s := &ldapSession{handle: new(ldap.LDAP), api: ldapAPI{
				firstAttribute: func(_ *ldap.LDAP, _ *ldap.LDAPMessage, c **ldap.BerElement) foundation.PWSTR {
					*c = new(ldap.BerElement)
					return &units[0]
				},
				memoryFree: func(foundation.PWSTR) { names++ }, berFree: func(*ldap.BerElement, int32) { cursors++ },
			}}
			_, err := s.readRawAttributes(new(ldap.LDAPMessage), true)
			if !errors.Is(err, ErrInvalidResult) || names != 1 || cursors != 1 {
				t.Fatalf("err=%v names=%d cursors=%d", err, names, cursors)
			}
		})
	}
}

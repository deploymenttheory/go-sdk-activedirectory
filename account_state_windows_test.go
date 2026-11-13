//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNativeAccountExpirationWireAndOwnership(t *testing.T) {
	for _, clear := range []bool{false, true} {
		for _, code := range []byte{0, 50} {
			t.Run(fmt.Sprintf("clear=%t/code=%d", clear, code), func(t *testing.T) {
				at := accountStateTime(t, "2026-11-13T12:22:33.1234567+01:00")
				wantValue := "134390425531234567"
				if clear {
					wantValue = "9223372036854775807"
				}
				mod := searchBER(0x30, []byte{10, 1, 2}, searchBER(0x30, searchBER(4, []byte("accountExpires")), searchBER(0x31, searchBER(4, []byte(wantValue)))))
				want := append(searchBER(4, []byte(objectGUIDTarget(objectTestGUID()))), searchBER(0x30, mod)...)
				fixture := newWriteWireFixture(t, 0x66, 0x67, want, nil, code)
				var owners searchNativeCounts
				client := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&owners))
				native := client.session.(*ldapSession)
				writes, reads := 0, 0
				client.session = objectWriteTestSession{testSession: testSession{read: func(context.Context, []string) (map[string][][]byte, error) {
					return identityTestRoot(CapabilityActiveDirectory), nil
				}, search: func(context.Context, SearchOptions) (searchCursor, error) {
					reads++
					object := accountTestEntry(512)
					object.Attributes["accountexpires"] = [][]byte{[]byte(wantValue)}
					return objectTestCursor(object), nil
				}, finish: native.close}, write: func(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
					writes++
					return native.ldapWrite(ctx, request)
				}}
				var result AccountExpirationMutationResult
				var err error
				if clear {
					result, err = client.ClearAccountExpiration(context.Background(), objectTestIdentity(), ObjectMutationOptions{})
				} else {
					result, err = client.SetAccountExpiration(context.Background(), SetAccountExpirationRequest{Identity: objectTestIdentity(), At: at})
				}
				if code == 0 {
					if err != nil || !result.Mutation.Verified || result.Mutation.State != ObjectWriteAccepted || reads != 2 || result.Expiration == nil {
						t.Fatal(result, err)
					}
					if clear && *result.Expiration.Value != math.MaxInt64 {
						t.Fatal(result)
					}
				} else if !hasLDAPCode(err, 50) || result.Mutation.State != ObjectWriteRejected || reads != 1 {
					t.Fatal(result, err)
				}
				if writes != 1 {
					t.Fatal(writes)
				}
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
				if owners != (searchNativeCounts{}) {
					t.Fatal(owners)
				}
			})
		}
	}
}

func TestNativeAccountStatePostfilterPagingAndLimits(t *testing.T) {
	for _, mode := range []string{"complete", "limit", "unknown", "permission", "lds-lock", "lds-password", "inactive"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() { done <- serveAccountStateWire(listener, mode) }()
			var owners searchNativeCounts
			client := searchWireClient(t, &searchWireFixture{listener: listener}, countedSearchAPI(&owners))
			native := client.session.(*ldapSession)
			client.session = testSession{read: func(context.Context, []string) (map[string][][]byte, error) {
				if strings.HasPrefix(mode, "lds-") {
					return identityTestRoot(CapabilityADLDS), nil
				}
				return identityTestRoot(CapabilityActiveDirectory), nil
			}, search: native.startSearch, finish: native.close}
			query := AccountStateQuery{Condition: AccountLockedOut, Search: SearchOptions{Scope: ScopeSubtree, PageSize: 3}}
			if mode == "limit" {
				query.Search.ResultLimit = 1
			}
			if mode == "lds-password" {
				query.Condition = AccountPasswordExpired
			}
			if mode == "inactive" {
				query.Condition = AccountInactive
				query.Boundary = accountStateTime(t, "2026-11-13T12:00:00Z")
			}
			result, err := client.SearchAccountState(context.Background(), query)
			if err != nil && mode == "inactive" {
				select {
				case wireErr := <-done:
					t.Fatalf("search: %v; wire: %v", err, wireErr)
				default:
				}
			}
			switch mode {
			case "complete", "lds-lock", "lds-password":
				if err != nil || !result.Complete || result.Scanned != 4 || len(result.Accounts) != 3 {
					t.Fatal(result, err)
				}
			case "inactive":
				if err != nil || !result.Complete || result.Scanned != 4 || len(result.Accounts) != 4 || result.Inactivity == nil || result.Inactivity.SynchronizationIntervalDays != 15 {
					t.Fatal(result, err)
				}
			case "limit":
				if err != nil || result.Complete || !result.MatchLimitReached || result.Scanned != 2 || len(result.Observation.Objects) != 3 || len(result.Accounts) != 1 {
					t.Fatal(result, err)
				}
			case "unknown":
				if !errors.Is(err, ErrAccountStateUnreadable) || result.Complete || len(result.Unknown) != 1 || len(result.Accounts) != 2 {
					t.Fatal(result, err)
				}
			case "permission":
				if !hasLDAPCode(err, 50) || result.Complete || len(result.Accounts) != 2 {
					t.Fatal(result, err)
				}
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("account-state responder did not stop")
			}
			if owners != (searchNativeCounts{}) {
				t.Fatalf("native ownership: %+v", owners)
			}
		})
	}
}

func serveAccountStateWire(listener net.Listener, mode string) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	pages, cleanups := 0, 0
	for {
		packet, err := readSearchBER(conn)
		if err != nil {
			return err
		}
		id, rest, err := takeSearchBER(packet, 2)
		if err != nil || len(rest) == 0 {
			return errors.New("invalid search envelope")
		}
		if rest[0] == 0x42 {
			wantPages := 2
			if mode == "limit" || mode == "permission" {
				wantPages = 1
			}
			if pages != wantPages {
				return fmt.Errorf("unexpected page count %d", pages)
			}
			if mode == "limit" && cleanups != 1 {
				return errors.New("match limit did not release cookie")
			}
			return nil
		}
		request, controls, err := takeSearchBER(rest, 0x63)
		if err != nil {
			return err
		}
		size, err := searchWirePageSize(controls)
		if err != nil {
			return err
		}
		filter, err := searchWireFilter(request)
		if err != nil {
			return err
		}
		if strings.Contains(string(filter), "msDS-User-Account-Control-Computed") || !strings.Contains(string(filter), "objectClass") {
			return errors.New("constructed predicate submitted as LDAP filter")
		}
		if strings.Contains(string(filter), "ms-DS-UserAccountAutoLocked") || strings.Contains(string(filter), "msDS-UserPasswordExpired") {
			return errors.New("constructed LDS predicate submitted as LDAP filter")
		}
		if mode == "inactive" {
			// Literal module-compatible UTC cutoff: 2026-11-13 minus 15 days.
			and, _, e1 := takeSearchBER(filter, 0xa0)
			_, remaining, e2 := takeSearchBER(and, 0xa1)
			not, _, e3 := takeSearchBER(remaining, 0xa2)
			ge, _, e4 := takeSearchBER(not, 0xa5)
			attribute, rest, e5 := takeSearchBER(ge, 4)
			value, tail, e6 := takeSearchBER(rest, 4)
			if errors.Join(e1, e2, e3, e4, e5, e6) != nil || string(attribute) != "lastLogonTimestamp" || string(value) != "134377488000000000" || len(tail) != 0 {
				return fmt.Errorf("inactivity predicate bytes %x", filter)
			}
		}
		cookie := []byte(nil)
		code := byte(0)
		if size == 0 {
			cleanups++
		} else {
			pages++
			if pages > 2 || size != 3 {
				return errors.New("unexpected account page request")
			}
			count := 3
			if pages == 2 {
				count = 1
			} else {
				cookie = []byte("next")
			}
			for i := 0; i < count; i++ {
				computed := []byte("16")
				if pages == 1 && i == 0 {
					computed = []byte("0")
				}
				attributes := append(searchWireAttribute("objectClass", []byte("user")), searchWireAttribute("objectGUID", objectTestGUID().Bytes())...)
				// Stale lockoutTime and stored UAC must not override computed zero.
				attributes = append(attributes, searchWireAttribute("lockoutTime", []byte("123456"))...)
				attributes = append(attributes, searchWireAttribute("userAccountControl", []byte("528"))...)
				if !(mode == "unknown" && pages == 1 && i == 2) {
					attributes = append(attributes, searchWireAttribute("msDS-User-Account-Control-Computed", computed)...)
				}
				if strings.HasPrefix(mode, "lds-") {
					attribute := "ms-DS-UserAccountAutoLocked"
					if mode == "lds-password" {
						attribute = "msDS-UserPasswordExpired"
					}
					text := []byte("TRUE")
					if pages == 1 && i == 0 {
						text = []byte("FALSE")
					}
					attributes = append(attributes, searchWireAttribute(attribute, text)...)
				}
				if mode == "inactive" && !(pages == 1 && i == 0) {
					stamp := []byte("134376624000000000")
					if pages == 1 && i == 1 {
						stamp = []byte("0")
					}
					attributes = append(attributes, searchWireAttribute("lastLogonTimestamp", stamp)...)
				}
				entry := searchBER(0x64, searchBER(4, []byte(fmt.Sprintf("CN=row%d-%d,DC=example", pages, i))), searchBER(0x30, attributes))
				if _, err := conn.Write(searchBER(0x30, searchBER(2, id), entry)); err != nil {
					return err
				}
			}
			if mode == "permission" {
				code = 50
			}
		}
		control := searchBER(0xa0, searchBER(0x30, searchBER(4, []byte("1.2.840.113556.1.4.319")), searchBER(4, searchBER(0x30, []byte{2, 1, 0}, searchBER(4, cookie)))))
		if _, err := conn.Write(searchBER(0x30, searchBER(2, id), searchBER(0x65, []byte{10, 1, code, 4, 0, 4, 0}), control)); err != nil {
			return err
		}
	}
}

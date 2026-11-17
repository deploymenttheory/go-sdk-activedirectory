//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_accounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/accounts"
)

func TestNativeAccountExpirationWireAndOwnership(t *testing.T) {
	for _, clear := range []bool{false, true} {
		for _, code := range []byte{0, 50} {
			t.Run(fmt.Sprintf("clear=%t/code=%d", clear, code), func(t *testing.T) {
				at := InternalAccountStateTime(t, "2026-11-13T12:22:33.1234567+01:00")
				wantValue := "134390425531234567"
				if clear {
					wantValue = "9223372036854775807"
				}
				mod := InternalSearchBER(
					0x30,
					[]byte{10, 1, 2},
					InternalSearchBER(
						0x30,
						InternalSearchBER(4, []byte("accountExpires")),
						InternalSearchBER(0x31, InternalSearchBER(4, []byte(wantValue))),
					),
				)
				want := append(
					InternalSearchBER(
						4,
						[]byte(admodel.InternalObjectGUIDTarget(InternalObjectTestGUID())),
					),
					InternalSearchBER(0x30, mod)...)
				fixture := InternalNewWriteWireFixture(t, 0x66, 0x67, want, nil, code)
				var owners InternalSearchNativeCounts
				client := InternalSearchWireClient(
					t,
					&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
					InternalCountedSearchAPI(&owners),
				)
				native := adengine.InternalClientSession(client).(*adengine.InternalLdapSession)
				writes, reads := 0, 0
				(*adengine.InternalClientSessionPointer(client)) = InternalObjectWriteTestSession{
					InternalTestSession: InternalTestSession{
						InternalRead: func(context.Context, []string) (map[string][][]byte, error) {
							return InternalIdentityTestRoot(admodel.CapabilityActiveDirectory), nil
						},
						InternalSearch: func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
							reads++
							object := InternalAccountTestEntry(512)
							object.Attributes["accountexpires"] = [][]byte{[]byte(wantValue)}
							return InternalObjectTestCursor(object), nil
						},
						InternalFinish: native.InternalClose,
					},
					InternalWrite: func(ctx context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
						writes++
						return native.InternalLdapWrite(ctx, request)
					},
				}
				var result admodel.AccountExpirationMutationResult
				var err error
				if clear {
					result, err = adservice_accounts.New(client).
						ClearAccountExpiration(context.Background(), InternalObjectTestIdentity(), admodel.ObjectMutationOptions{})
				} else {
					result, err = adservice_accounts.New(client).
						SetAccountExpiration(context.Background(), admodel.SetAccountExpirationRequest{Identity: InternalObjectTestIdentity(), At: at})
				}
				if code == 0 {
					if err != nil || !result.Mutation.Verified ||
						result.Mutation.State != admodel.ObjectWriteAccepted ||
						reads != 2 ||
						result.Expiration == nil {
						t.Fatal(result, err)
					}
					if clear && *result.Expiration.Value != math.MaxInt64 {
						t.Fatal(result)
					}
				} else if !InternalHasLDAPCode(err, 50) || result.Mutation.State != admodel.ObjectWriteRejected || reads != 1 {
					t.Fatal(result, err)
				}
				if writes != 1 {
					t.Fatal(writes)
				}
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
				if owners != (InternalSearchNativeCounts{}) {
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
			go func() { done <- InternalServeAccountStateWire(listener, mode) }()
			var owners InternalSearchNativeCounts
			client := InternalSearchWireClient(
				t,
				&InternalSearchWireFixture{InternalListener: listener},
				InternalCountedSearchAPI(&owners),
			)
			native := adengine.InternalClientSession(client).(*adengine.InternalLdapSession)
			(*adengine.InternalClientSessionPointer(client)) = InternalTestSession{
				InternalRead: func(context.Context, []string) (map[string][][]byte, error) {
					if strings.HasPrefix(mode, "lds-") {
						return InternalIdentityTestRoot(admodel.CapabilityADLDS), nil
					}
					return InternalIdentityTestRoot(admodel.CapabilityActiveDirectory), nil
				},
				InternalSearch: native.InternalStartSearch,
				InternalFinish: native.InternalClose,
			}
			query := admodel.AccountStateQuery{
				Condition: admodel.AccountLockedOut,
				Search:    admodel.SearchOptions{Scope: admodel.ScopeSubtree, PageSize: 3},
			}
			if mode == "limit" {
				query.Search.ResultLimit = 1
			}
			if mode == "lds-password" {
				query.Condition = admodel.AccountPasswordExpired
			}
			if mode == "inactive" {
				query.Condition = admodel.AccountInactive
				query.Boundary = InternalAccountStateTime(t, "2026-11-13T12:00:00Z")
			}
			result, err := adservice_accounts.New(client).
				SearchAccountState(context.Background(), query)
			if err != nil && mode == "inactive" {
				select {
				case wireErr := <-done:
					t.Fatalf("search: %v; wire: %v", err, wireErr)
				default:
				}
			}
			switch mode {
			case "complete", "lds-lock", "lds-password":
				if err != nil || !result.Complete || result.Scanned != 4 ||
					len(result.Accounts) != 3 {
					t.Fatal(result, err)
				}
			case "inactive":
				if err != nil || !result.Complete || result.Scanned != 4 ||
					len(result.Accounts) != 4 ||
					result.Inactivity == nil ||
					result.Inactivity.SynchronizationIntervalDays != 15 {
					t.Fatal(result, err)
				}
			case "limit":
				if err != nil || result.Complete || !result.MatchLimitReached ||
					result.Scanned != 2 ||
					len(result.Observation.Objects) != 3 ||
					len(result.Accounts) != 1 {
					t.Fatal(result, err)
				}
			case "unknown":
				if !errors.Is(err, admodel.ErrAccountStateUnreadable) || result.Complete ||
					len(result.Unknown) != 1 ||
					len(result.Accounts) != 2 {
					t.Fatal(result, err)
				}
			case "permission":
				if !InternalHasLDAPCode(err, 50) || result.Complete || len(result.Accounts) != 2 {
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
			if owners != (InternalSearchNativeCounts{}) {
				t.Fatalf("native ownership: %+v", owners)
			}
		})
	}
}

func InternalServeAccountStateWire(listener net.Listener, mode string) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	pages, cleanups := 0, 0
	for {
		packet, err := InternalReadSearchBER(conn)
		if err != nil {
			return err
		}
		id, rest, err := InternalTakeSearchBER(packet, 2)
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
		request, controls, err := InternalTakeSearchBER(rest, 0x63)
		if err != nil {
			return err
		}
		size, err := InternalSearchWirePageSize(controls)
		if err != nil {
			return err
		}
		filter, err := InternalSearchWireFilter(request)
		if err != nil {
			return err
		}
		if strings.Contains(string(filter), "msDS-User-Account-Control-Computed") ||
			!strings.Contains(string(filter), "objectClass") {
			return errors.New("constructed predicate submitted as LDAP filter")
		}
		if strings.Contains(string(filter), "ms-DS-UserAccountAutoLocked") ||
			strings.Contains(string(filter), "msDS-UserPasswordExpired") {
			return errors.New("constructed LDS predicate submitted as LDAP filter")
		}
		if mode == "inactive" {
			// Literal module-compatible UTC cutoff: 2026-11-13 minus 15 days.
			and, _, e1 := InternalTakeSearchBER(filter, 0xa0)
			_, remaining, e2 := InternalTakeSearchBER(and, 0xa1)
			not, _, e3 := InternalTakeSearchBER(remaining, 0xa2)
			ge, _, e4 := InternalTakeSearchBER(not, 0xa5)
			attribute, rest, e5 := InternalTakeSearchBER(ge, 4)
			value, tail, e6 := InternalTakeSearchBER(rest, 4)
			if errors.Join(e1, e2, e3, e4, e5, e6) != nil ||
				string(attribute) != "lastLogonTimestamp" ||
				string(value) != "134377488000000000" ||
				len(tail) != 0 {
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
				attributes := append(
					InternalSearchWireAttribute("objectClass", []byte("user")),
					InternalSearchWireAttribute("objectGUID", InternalObjectTestGUID().Bytes())...)
				// Stale lockoutTime and stored UAC must not override computed zero.
				attributes = append(
					attributes,
					InternalSearchWireAttribute("lockoutTime", []byte("123456"))...)
				attributes = append(
					attributes,
					InternalSearchWireAttribute("userAccountControl", []byte("528"))...)
				if !(mode == "unknown" && pages == 1 && i == 2) {
					attributes = append(
						attributes,
						InternalSearchWireAttribute(
							"msDS-User-Account-Control-Computed",
							computed,
						)...)
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
					attributes = append(attributes, InternalSearchWireAttribute(attribute, text)...)
				}
				if mode == "inactive" && !(pages == 1 && i == 0) {
					stamp := []byte("134376624000000000")
					if pages == 1 && i == 1 {
						stamp = []byte("0")
					}
					attributes = append(
						attributes,
						InternalSearchWireAttribute("lastLogonTimestamp", stamp)...)
				}
				entry := InternalSearchBER(
					0x64,
					InternalSearchBER(4, []byte(fmt.Sprintf("CN=row%d-%d,DC=example", pages, i))),
					InternalSearchBER(0x30, attributes),
				)
				if _, err := conn.Write(
					InternalSearchBER(0x30, InternalSearchBER(2, id), entry),
				); err != nil {
					return err
				}
			}
			if mode == "permission" {
				code = 50
			}
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
		if _, err := conn.Write(
			InternalSearchBER(
				0x30,
				InternalSearchBER(2, id),
				InternalSearchBER(0x65, []byte{10, 1, code, 4, 0, 4, 0}),
				control,
			),
		); err != nil {
			return err
		}
	}
}

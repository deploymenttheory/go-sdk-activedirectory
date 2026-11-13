package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestAccountStateTimePredicatesAndUnreadableValues(t *testing.T) {
	asOf := accountStateTime(t, "2026-11-13T12:00:00Z")
	boundary := accountStateTime(t, "2026-11-20T12:00:00Z")
	for _, condition := range []AccountStateCondition{AccountExpired, AccountExpiring, AccountInactive} {
		for _, raw := range []string{"before", "equal", "after", "end", "beyond", "zero", "never", "missing", "malformed"} {
			t.Run(fmt.Sprintf("%d/%s", condition, raw), func(t *testing.T) {
				query := AccountStateQuery{Condition: condition, AsOf: asOf, Boundary: boundary}
				attribute := "accountExpires"
				if condition == AccountInactive {
					attribute = "lastLogonTimestamp"
					query = AccountStateQuery{Condition: condition, Boundary: asOf}
				}
				object := accountTestEntry(512)
				object.RequestedProperties = []string{attribute}
				at := asOf.Add(-100)
				switch raw {
				case "equal":
					at = asOf
				case "after":
					at = asOf.Add(100)
				case "end":
					at = boundary
				case "beyond":
					at = boundary.Add(100)
				}
				stamp, _ := finiteAccountTime(at)
				text := stamp.LDAPString()
				switch raw {
				case "zero":
					text = "0"
				case "never":
					text = "9223372036854775807"
				case "malformed":
					text = "invalid"
				}
				if raw != "missing" {
					object.Attributes[strings.ToLower(attribute)] = [][]byte{[]byte(text)}
				}
				match, err := matchAccountState(object, DirectoryADDS, query)
				unknown := raw == "malformed" || (raw == "missing" && condition != AccountInactive)
				if unknown {
					if err == nil {
						t.Fatal(match, err)
					}
					return
				}
				want := raw == "before"
				if condition == AccountExpiring {
					want = raw == "equal" || raw == "after"
				} else if condition == AccountInactive {
					want = raw == "before" || raw == "missing" || raw == "zero"
				}
				if err != nil || match != want {
					t.Fatal(match, want, err)
				}
			})
		}
	}
}

func TestAccountStateStoredAndComputedPredicates(t *testing.T) {
	for _, kind := range []DirectoryType{DirectoryADDS, DirectoryADLDS} {
		for _, condition := range []AccountStateCondition{AccountDisabled, AccountLockedOut, AccountPasswordExpired, AccountPasswordNeverExpires} {
			for _, set := range []bool{false, true} {
				object := accountTestEntry(0x800010) // Stored lockout/expiry never determine computed state.
				object.Attributes["lockouttime"] = [][]byte{[]byte("123456")}
				attribute, text := "useraccountcontrol", "0"
				switch condition {
				case AccountDisabled:
					if set {
						text = "2"
					}
					if kind == DirectoryADLDS {
						attribute = "msds-useraccountdisabled"
						text = "FALSE"
						if set {
							text = "TRUE"
						}
					}
				case AccountPasswordNeverExpires:
					if set {
						text = "65536"
					}
					if kind == DirectoryADLDS {
						attribute = "msds-userdontexpirepassword"
						text = "FALSE"
						if set {
							text = "TRUE"
						}
					}
				case AccountLockedOut:
					attribute = "msds-user-account-control-computed"
					if set {
						text = "16"
					}
					if kind == DirectoryADLDS {
						attribute, text = "ms-ds-useraccountautolocked", "FALSE"
						if set {
							text = "TRUE"
						}
					}
				case AccountPasswordExpired:
					attribute = "msds-user-account-control-computed"
					if set {
						text = "8388608"
					}
					if kind == DirectoryADLDS {
						attribute, text = "msds-userpasswordexpired", "FALSE"
						if set {
							text = "TRUE"
						}
					}
				}
				object.Attributes[attribute] = [][]byte{[]byte(text)}
				match, err := matchAccountState(object, kind, AccountStateQuery{Condition: condition})
				if err != nil || match != set {
					t.Fatal(kind, condition, match, err)
				}
				object.Attributes[attribute] = [][]byte{[]byte("invalid")}
				if _, err := matchAccountState(object, kind, AccountStateQuery{Condition: condition}); !errors.Is(err, ErrInvalidValue) {
					t.Fatal(kind, condition, err)
				}
				delete(object.Attributes, attribute)
				if _, err := matchAccountState(object, kind, AccountStateQuery{Condition: condition}); !errors.Is(err, ErrAttributeUnavailable) {
					t.Fatal(kind, condition, err)
				}
			}
		}
	}
}

func TestAccountInactiveModuleCriteriaAndIntervalObservation(t *testing.T) {
	boundary := accountStateTime(t, "2026-11-13T12:00:00Z")
	for _, mode := range []string{"default", "configured", "zero", "lds", "hidden", "malformed", "negative", "overflow", "denied", "cutoff-underflow", "old-functional-level"} {
		t.Run(mode, func(t *testing.T) {
			searches, domainReads := 0, 0
			days := 15
			if mode == "configured" {
				days = 8
			}
			if mode == "zero" {
				days = 0
			}
			query := AccountStateQuery{Condition: AccountInactive, Boundary: boundary, Search: SearchOptions{Base: "OU=People,DC=example", Scope: ScopeSubtree}}
			if mode == "cutoff-underflow" {
				query.Boundary = accountStateTime(t, "1601-01-02T00:00:00Z")
			}
			wantCutoff := query.Boundary.AddDate(0, 0, -days)
			client := objectTestClient(t, nil, func(_ context.Context, options SearchOptions) (searchCursor, error) {
				searches++
				stamp, _ := finiteAccountTime(wantCutoff)
				if !strings.Contains(options.Filter, "(!(lastLogonTimestamp>="+stamp.LDAPString()+"))") || options.Base != query.Search.Base {
					t.Fatal(options)
				}
				// The server predicate includes null/zero and excludes equality.
				missing, zero, older := accountTestEntry(512), accountTestEntry(512), accountTestEntry(512)
				zero.Attributes["lastlogontimestamp"] = [][]byte{[]byte("0")}
				old, _ := finiteAccountTime(wantCutoff.Add(-time.Hour))
				older.Attributes["lastlogontimestamp"] = [][]byte{[]byte(old.LDAPString())}
				return objectTestCursor(missing, zero, older), nil
			}, func(context.Context, ldapWriteRequest) ldapWriteAttempt { t.Fatal("write"); return ldapWriteAttempt{} })
			session := client.session.(objectWriteTestSession)
			session.base = func(_ context.Context, base string, properties []string) (map[string][][]byte, error) {
				if base == "" {
					if mode == "lds" {
						return identityTestRoot(CapabilityADLDS), nil
					}
					root := identityTestRoot(CapabilityActiveDirectory)
					if mode == "old-functional-level" {
						root["domainfunctionality"] = [][]byte{[]byte("1")}
					}
					return root, nil
				}
				domainReads++
				if base != "DC=example" || len(properties) != 1 || properties[0] != "msDS-LogonTimeSyncInterval" {
					t.Fatal(base, properties)
				}
				attrs := map[string][][]byte{}
				switch mode {
				case "configured", "zero":
					attrs["msds-logontimesyncinterval"] = [][]byte{[]byte(fmt.Sprint(days))}
				case "malformed":
					attrs["msds-logontimesyncinterval"] = [][]byte{[]byte("invalid")}
				case "negative":
					attrs["msds-logontimesyncinterval"] = [][]byte{[]byte("-1")}
				case "overflow":
					attrs["msds-logontimesyncinterval"] = [][]byte{[]byte("2147483648")}
				case "denied":
					return map[string][][]byte{"description": {[]byte("partial")}}, &LDAPError{Code: 50}
				}
				return attrs, nil
			}
			client.session = session
			result, err := client.SearchAccountState(context.Background(), query)
			bad := mode == "malformed" || mode == "negative" || mode == "overflow" || mode == "denied" || mode == "cutoff-underflow" || mode == "old-functional-level"
			if bad {
				if err == nil || searches != 0 || result.Complete || result.Inactivity == nil {
					t.Fatal(result, err, searches)
				}
				if mode == "denied" && (result.Inactivity.DomainReadComplete || len(result.Inactivity.Domain.Attributes) != 1) {
					t.Fatal(result.Inactivity)
				}
				return
			}
			if err != nil || !result.Complete || len(result.Accounts) != 3 || len(result.Unknown) != 0 || searches != 1 {
				t.Fatal(result, err)
			}
			observed := result.Inactivity
			if observed == nil || observed.SynchronizationIntervalDays != int32(days) || !observed.Cutoff.Equal(wantCutoff) || observed.Defaulted != (mode != "configured" && mode != "zero") {
				t.Fatal(observed)
			}
			if mode == "lds" && domainReads != 0 {
				t.Fatal(domainReads)
			}
			if mode != "lds" && (domainReads != 1 || !observed.DomainReadComplete) {
				t.Fatal(domainReads, observed)
			}
			if _, state := result.Accounts[0].Attribute("lastLogonTimestamp"); state != AttributeAbsent {
				t.Fatal(state)
			}
		})
	}
}

func TestAccountStateQueryRejectsCombinedOrAmbiguousTimeInputs(t *testing.T) {
	at := accountStateTime(t, "2026-11-13T12:00:00Z")
	for _, query := range []AccountStateQuery{
		{}, {Condition: AccountDisabled, AsOf: at}, {Condition: AccountExpired}, {Condition: AccountExpired, AsOf: at, Boundary: at},
		{Condition: AccountExpiring, AsOf: at, Boundary: at.Add(-1)}, {Condition: AccountInactive}, {Condition: AccountInactive, Boundary: at, AsOf: at},
		{Condition: AccountLockedOut, ScanLimit: -1}, {Condition: AccountLockedOut, Kind: 99},
		{Condition: AccountLockedOut, Search: SearchOptions{Filter: "(cn=*)", TypedFilter: FilterPresent("cn")}},
		{Condition: AccountLockedOut, Search: SearchOptions{Properties: []string{"1.1"}}},
	} {
		var client *Client
		if _, err := client.SearchAccountState(context.Background(), query); err == nil || errors.Is(err, ErrClosed) {
			t.Fatal(query, err)
		}
	}
}

func TestAccountStateScanAndMatchLimitsAreIndependent(t *testing.T) {
	for _, mode := range []string{"complete", "scan-limit", "match-limit", "unknown", "native-error", "cleanup-error", "wrong-class", "user-selection"} {
		t.Run(mode, func(t *testing.T) {
			pages, closes := 0, 0
			query := AccountStateQuery{Condition: AccountLockedOut, ScanLimit: 10, Search: SearchOptions{Scope: ScopeSubtree, PageSize: 3, TypedFilter: FilterEqual("department", FilterText("R&D"))}}
			if mode == "scan-limit" {
				query.ScanLimit = 2
			}
			if mode == "match-limit" {
				query.Search.ResultLimit = 1
			}
			if mode == "user-selection" {
				query.Kind = AccountStateUsers
			}
			denied := &LDAPError{Code: 50}
			client := objectTestClient(t, nil, func(_ context.Context, options SearchOptions) (searchCursor, error) {
				if options.Base != "DC=example" || options.ResultLimit != 0 || !strings.Contains(options.Filter, "(department=R&D)") || strings.Contains(options.Filter, "msDS-User-Account-Control-Computed") {
					t.Fatal(options)
				}
				if mode == "user-selection" && !strings.Contains(options.Filter, "(!(objectClass=computer))") {
					t.Fatal(options.Filter)
				}
				return testSearchCursor{read: func(_ context.Context, size uint32) ([]Object, bool, error) {
					pages++
					if pages > 2 {
						t.Fatal("unbounded paging")
					}
					count := 3
					if mode == "scan-limit" {
						if size != 2 {
							t.Fatal(size)
						}
						count = 2
					}
					objects := make([]Object, count)
					for i := range objects {
						objects[i] = accountTestEntry(512)
						objects[i].DistinguishedName = fmt.Sprintf("CN=row%d-%d,DC=example", pages, i)
						if i != 0 {
							objects[i].Attributes["msds-user-account-control-computed"] = [][]byte{[]byte("16")}
						}
					}
					if mode == "unknown" {
						delete(objects[0].Attributes, "msds-user-account-control-computed")
					}
					if mode == "wrong-class" {
						objects[0].Attributes["objectclass"] = [][]byte{[]byte("group")}
					}
					if mode == "native-error" {
						return objects, false, denied
					}
					return objects, pages == 2, nil
				}, finish: func() error {
					closes++
					if mode == "cleanup-error" {
						return denied
					}
					return nil
				}}, nil
			}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
				t.Fatal("search wrote")
				return ldapWriteAttempt{}
			})
			result, err := client.SearchAccountState(context.Background(), query)
			if closes != 1 {
				t.Fatal(closes)
			}
			switch mode {
			case "complete", "user-selection":
				if err != nil || !result.Complete || !result.Observation.Complete || result.Scanned != 6 || len(result.Accounts) != 4 {
					t.Fatal(result, err)
				}
			case "scan-limit":
				if err != nil || result.Complete || !result.ScanLimitReached || result.MatchLimitReached || result.Scanned != 2 || len(result.Accounts) != 1 || pages != 1 {
					t.Fatal(result, err)
				}
			case "match-limit":
				if err != nil || result.Complete || !result.MatchLimitReached || result.ScanLimitReached || result.Scanned != 2 || len(result.Accounts) != 1 || len(result.Observation.Objects) != 3 || pages != 1 {
					t.Fatal(result, err)
				}
			case "unknown", "wrong-class":
				if !errors.Is(err, ErrAccountStateUnreadable) || result.Complete || !result.Observation.Complete || len(result.Unknown) != 2 || len(result.Accounts) != 4 {
					t.Fatal(result, err)
				}
			default:
				if !errors.Is(err, denied) || result.Complete || result.Observation.Complete || len(result.Accounts) == 0 {
					t.Fatal(result, err)
				}
			}
		})
	}
}

func TestAccountStateScopesAndGCRejection(t *testing.T) {
	for _, mode := range []string{"lds", "gc", "missing-partition", "computer"} {
		t.Run(mode, func(t *testing.T) {
			searches := 0
			client := objectTestClient(t, nil, func(_ context.Context, options SearchOptions) (searchCursor, error) {
				searches++
				if mode == "computer" && !strings.Contains(options.Filter, "(objectClass=computer)") {
					t.Fatal(options)
				}
				if mode == "lds" && !strings.Contains(options.Filter, "(objectClass=msDS-BindableObject)") {
					t.Fatal(options)
				}
				return objectTestCursor(), nil
			}, func(context.Context, ldapWriteRequest) ldapWriteAttempt { t.Fatal("write"); return ldapWriteAttempt{} })
			if mode == "gc" {
				client.config.Endpoint.Port = 3268
			}
			if mode == "lds" {
				session := client.session.(objectWriteTestSession)
				session.read = func(context.Context, []string) (map[string][][]byte, error) {
					return identityTestRoot(CapabilityADLDS), nil
				}
				client.session = session
			}
			query := AccountStateQuery{Condition: AccountDisabled}
			if mode == "missing-partition" {
				query.Search.Base = "DC=missing"
			}
			if mode == "computer" {
				query.Kind = AccountStateComputers
			}
			result, err := client.SearchAccountState(context.Background(), query)
			if mode == "gc" || mode == "missing-partition" {
				if err == nil || searches != 0 || result.Complete {
					t.Fatal(result, err, searches)
				}
			} else if err != nil || !result.Complete || searches != 1 {
				t.Fatal(result, err, searches)
			}
		})
	}
}

func TestAccountStateClassBoundariesAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		classes   []string
		kind      DirectoryType
		selection AccountStateKind
		valid     bool
	}{
		{[]string{"user", "computer"}, DirectoryADDS, AccountStateComputers, true},
		{[]string{"user", "computer", "msDS-GroupManagedServiceAccount"}, DirectoryADDS, AccountStateAll, true},
		{[]string{"inetOrgPerson"}, DirectoryADLDS, AccountStateUsers, true},
		{[]string{"msDS-BindableObject", "customPrincipal"}, DirectoryADLDS, AccountStateAll, true},
		{[]string{"group"}, DirectoryADDS, AccountStateAll, false},
		{[]string{"user", "computer"}, DirectoryADDS, AccountStateUsers, false},
		{[]string{"msDS-BindableObject"}, DirectoryADDS, AccountStateAll, false},
	} {
		object := accountTestEntry(514)
		object.Attributes["objectclass"] = nil
		for _, class := range tc.classes {
			object.Attributes["objectclass"] = append(object.Attributes["objectclass"], []byte(class))
		}
		object.Attributes["msds-useraccountdisabled"] = [][]byte{[]byte("TRUE")}
		match, err := matchAccountState(object, tc.kind, AccountStateQuery{Condition: AccountDisabled, Kind: tc.selection})
		if (err == nil) != tc.valid || (tc.valid && !match) {
			t.Fatal(tc, match, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closes := 0
	result := AccountStateSearchResult{Directory: DirectoryADDS}
	err := collectAccountState(ctx, testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) {
		cancel()
		return []Object{accountTestEntry(514)}, false, nil
	}, finish: func() error { closes++; return nil }}, SearchOptions{PageSize: 1}, AccountStateQuery{Condition: AccountDisabled, ScanLimit: 10}, &result)
	if !errors.Is(err, context.Canceled) || result.Complete || result.Scanned != 0 || len(result.Observation.Objects) != 1 || closes != 1 {
		t.Fatal(result, err, closes)
	}
}

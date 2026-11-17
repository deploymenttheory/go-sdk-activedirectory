package acceptance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_accounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/accounts"
)

func TestAccountStateTimePredicatesAndUnreadableValues(t *testing.T) {
	asOf := InternalAccountStateTime(t, "2026-11-13T12:00:00Z")
	boundary := InternalAccountStateTime(t, "2026-11-20T12:00:00Z")
	for _, condition := range []admodel.AccountStateCondition{admodel.AccountExpired, admodel.AccountExpiring, admodel.AccountInactive} {
		for _, raw := range []string{"before", "equal", "after", "end", "beyond", "zero", "never", "missing", "malformed"} {
			t.Run(fmt.Sprintf("%d/%s", condition, raw), func(t *testing.T) {
				query := admodel.AccountStateQuery{
					Condition: condition,
					AsOf:      asOf,
					Boundary:  boundary,
				}
				attribute := "accountExpires"
				if condition == admodel.AccountInactive {
					attribute = "lastLogonTimestamp"
					query = admodel.AccountStateQuery{Condition: condition, Boundary: asOf}
				}
				object := InternalAccountTestEntry(512)
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
				stamp, _ := admodel.InternalFiniteAccountTime(at)
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
				match, err := admodel.InternalMatchAccountState(
					object,
					admodel.DirectoryADDS,
					query,
				)
				unknown := raw == "malformed" ||
					(raw == "missing" && condition != admodel.AccountInactive)
				if unknown {
					if err == nil {
						t.Fatal(match, err)
					}
					return
				}
				want := raw == "before"
				if condition == admodel.AccountExpiring {
					want = raw == "equal" || raw == "after"
				} else if condition == admodel.AccountInactive {
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
	for _, kind := range []admodel.DirectoryType{admodel.DirectoryADDS, admodel.DirectoryADLDS} {
		for _, condition := range []admodel.AccountStateCondition{admodel.AccountDisabled, admodel.AccountLockedOut, admodel.AccountPasswordExpired, admodel.AccountPasswordNeverExpires} {
			for _, set := range []bool{false, true} {
				object := InternalAccountTestEntry(
					0x800010,
				) // Stored lockout/expiry never determine computed state.
				object.Attributes["lockouttime"] = [][]byte{[]byte("123456")}
				attribute, text := "useraccountcontrol", "0"
				switch condition {
				case admodel.AccountDisabled:
					if set {
						text = "2"
					}
					if kind == admodel.DirectoryADLDS {
						attribute = "msds-useraccountdisabled"
						text = "FALSE"
						if set {
							text = "TRUE"
						}
					}
				case admodel.AccountPasswordNeverExpires:
					if set {
						text = "65536"
					}
					if kind == admodel.DirectoryADLDS {
						attribute = "msds-userdontexpirepassword"
						text = "FALSE"
						if set {
							text = "TRUE"
						}
					}
				case admodel.AccountLockedOut:
					attribute = "msds-user-account-control-computed"
					if set {
						text = "16"
					}
					if kind == admodel.DirectoryADLDS {
						attribute, text = "ms-ds-useraccountautolocked", "FALSE"
						if set {
							text = "TRUE"
						}
					}
				case admodel.AccountPasswordExpired:
					attribute = "msds-user-account-control-computed"
					if set {
						text = "8388608"
					}
					if kind == admodel.DirectoryADLDS {
						attribute, text = "msds-userpasswordexpired", "FALSE"
						if set {
							text = "TRUE"
						}
					}
				}
				object.Attributes[attribute] = [][]byte{[]byte(text)}
				match, err := admodel.InternalMatchAccountState(
					object,
					kind,
					admodel.AccountStateQuery{Condition: condition},
				)
				if err != nil || match != set {
					t.Fatal(kind, condition, match, err)
				}
				object.Attributes[attribute] = [][]byte{[]byte("invalid")}
				if _, err := admodel.InternalMatchAccountState(
					object,
					kind,
					admodel.AccountStateQuery{Condition: condition},
				); !errors.Is(
					err,
					admodel.ErrInvalidValue,
				) {
					t.Fatal(kind, condition, err)
				}
				delete(object.Attributes, attribute)
				if _, err := admodel.InternalMatchAccountState(
					object,
					kind,
					admodel.AccountStateQuery{Condition: condition},
				); !errors.Is(
					err,
					admodel.ErrAttributeUnavailable,
				) {
					t.Fatal(kind, condition, err)
				}
			}
		}
	}
}

func TestAccountInactiveModuleCriteriaAndIntervalObservation(t *testing.T) {
	boundary := InternalAccountStateTime(t, "2026-11-13T12:00:00Z")
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
			query := admodel.AccountStateQuery{
				Condition: admodel.AccountInactive,
				Boundary:  boundary,
				Search: admodel.SearchOptions{
					Base:  "OU=People,DC=example",
					Scope: admodel.ScopeSubtree,
				},
			}
			if mode == "cutoff-underflow" {
				query.Boundary = InternalAccountStateTime(t, "1601-01-02T00:00:00Z")
			}
			wantCutoff := query.Boundary.AddDate(0, 0, -days)
			client := InternalObjectTestClient(
				t,
				nil,
				func(_ context.Context, options admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					searches++
					stamp, _ := admodel.InternalFiniteAccountTime(wantCutoff)
					if !strings.Contains(
						options.Filter,
						"(!(lastLogonTimestamp>="+stamp.LDAPString()+"))",
					) ||
						options.Base != query.Search.Base {
						t.Fatal(options)
					}
					// The server predicate includes null/zero and excludes equality.
					missing, zero, older := InternalAccountTestEntry(
						512,
					), InternalAccountTestEntry(
						512,
					), InternalAccountTestEntry(
						512,
					)
					zero.Attributes["lastlogontimestamp"] = [][]byte{[]byte("0")}
					old, _ := admodel.InternalFiniteAccountTime(wantCutoff.Add(-time.Hour))
					older.Attributes["lastlogontimestamp"] = [][]byte{[]byte(old.LDAPString())}
					return InternalObjectTestCursor(missing, zero, older), nil
				},
				func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					t.Fatal("write")
					return admodel.InternalLdapWriteAttempt{}
				},
			)
			session := adengine.InternalClientSession(client).(InternalObjectWriteTestSession)
			session.InternalBase = func(_ context.Context, base string, properties []string) (map[string][][]byte, error) {
				if base == "" {
					if mode == "lds" {
						return InternalIdentityTestRoot(admodel.CapabilityADLDS), nil
					}
					root := InternalIdentityTestRoot(admodel.CapabilityActiveDirectory)
					if mode == "old-functional-level" {
						root["domainfunctionality"] = [][]byte{[]byte("1")}
					}
					return root, nil
				}
				domainReads++
				if base != "DC=example" || len(properties) != 1 ||
					properties[0] != "msDS-LogonTimeSyncInterval" {
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
					return map[string][][]byte{
							"description": {[]byte("partial")},
						}, &admodel.LDAPError{
							Code: 50,
						}
				}
				return attrs, nil
			}
			(*adengine.InternalClientSessionPointer(client)) = session
			result, err := adservice_accounts.New(client).
				SearchAccountState(context.Background(), query)
			bad := mode == "malformed" || mode == "negative" || mode == "overflow" ||
				mode == "denied" ||
				mode == "cutoff-underflow" ||
				mode == "old-functional-level"
			if bad {
				if err == nil || searches != 0 || result.Complete || result.Inactivity == nil {
					t.Fatal(result, err, searches)
				}
				if mode == "denied" &&
					(result.Inactivity.DomainReadComplete || len(result.Inactivity.Domain.Attributes) != 1) {
					t.Fatal(result.Inactivity)
				}
				return
			}
			if err != nil || !result.Complete || len(result.Accounts) != 3 ||
				len(result.Unknown) != 0 ||
				searches != 1 {
				t.Fatal(result, err)
			}
			observed := result.Inactivity
			if observed == nil || observed.SynchronizationIntervalDays != int32(days) ||
				!observed.Cutoff.Equal(wantCutoff) ||
				observed.Defaulted != (mode != "configured" && mode != "zero") {
				t.Fatal(observed)
			}
			if mode == "lds" && domainReads != 0 {
				t.Fatal(domainReads)
			}
			if mode != "lds" && (domainReads != 1 || !observed.DomainReadComplete) {
				t.Fatal(domainReads, observed)
			}
			if _, state := result.Accounts[0].Attribute(
				"lastLogonTimestamp",
			); state != admodel.AttributeAbsent {
				t.Fatal(state)
			}
		})
	}
}

func TestAccountStateQueryRejectsCombinedOrAmbiguousTimeInputs(t *testing.T) {
	at := InternalAccountStateTime(t, "2026-11-13T12:00:00Z")
	for _, query := range []admodel.AccountStateQuery{
		{},
		{Condition: admodel.AccountDisabled, AsOf: at},
		{Condition: admodel.AccountExpired},
		{Condition: admodel.AccountExpired, AsOf: at, Boundary: at},
		{Condition: admodel.AccountExpiring, AsOf: at, Boundary: at.Add(-1)},
		{Condition: admodel.AccountInactive},
		{Condition: admodel.AccountInactive, Boundary: at, AsOf: at},
		{Condition: admodel.AccountLockedOut, ScanLimit: -1},
		{Condition: admodel.AccountLockedOut, Kind: 99},
		{Condition: admodel.AccountLockedOut, Search: admodel.SearchOptions{Filter: "(cn=*)", TypedFilter: admodel.FilterPresent("cn")}},
		{Condition: admodel.AccountLockedOut, Search: admodel.SearchOptions{Properties: []string{"1.1"}}},
	} {
		var client *adengine.Client
		if _, err := adservice_accounts.New(client).
			SearchAccountState(context.Background(), query); err == nil ||
			errors.Is(err, admodel.ErrClosed) {
			t.Fatal(query, err)
		}
	}
}

func TestAccountStateScanAndMatchLimitsAreIndependent(t *testing.T) {
	for _, mode := range []string{"complete", "scan-limit", "match-limit", "unknown", "native-error", "cleanup-error", "wrong-class", "user-selection"} {
		t.Run(mode, func(t *testing.T) {
			pages, closes := 0, 0
			query := admodel.AccountStateQuery{
				Condition: admodel.AccountLockedOut,
				ScanLimit: 10,
				Search: admodel.SearchOptions{
					Scope:       admodel.ScopeSubtree,
					PageSize:    3,
					TypedFilter: admodel.FilterEqual("department", admodel.FilterText("R&D")),
				},
			}
			if mode == "scan-limit" {
				query.ScanLimit = 2
			}
			if mode == "match-limit" {
				query.Search.ResultLimit = 1
			}
			if mode == "user-selection" {
				query.Kind = admodel.AccountStateUsers
			}
			denied := &admodel.LDAPError{Code: 50}
			client := InternalObjectTestClient(
				t,
				nil,
				func(_ context.Context, options admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					if options.Base != "DC=example" || options.ResultLimit != 0 ||
						!strings.Contains(options.Filter, "(department=R&D)") ||
						strings.Contains(options.Filter, "msDS-User-Account-Control-Computed") {
						t.Fatal(options)
					}
					if mode == "user-selection" &&
						!strings.Contains(options.Filter, "(!(objectClass=computer))") {
						t.Fatal(options.Filter)
					}
					return InternalTestSearchCursor{
						InternalRead: func(_ context.Context, size uint32) ([]admodel.Object, bool, error) {
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
							objects := make([]admodel.Object, count)
							for i := range objects {
								objects[i] = InternalAccountTestEntry(512)
								objects[i].DistinguishedName = fmt.Sprintf(
									"CN=row%d-%d,DC=example",
									pages,
									i,
								)
								if i != 0 {
									objects[i].Attributes["msds-user-account-control-computed"] = [][]byte{
										[]byte("16"),
									}
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
						},
						InternalFinish: func() error {
							closes++
							if mode == "cleanup-error" {
								return denied
							}
							return nil
						},
					}, nil
				},
				func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					t.Fatal("search wrote")
					return admodel.InternalLdapWriteAttempt{}
				},
			)
			result, err := adservice_accounts.New(client).
				SearchAccountState(context.Background(), query)
			if closes != 1 {
				t.Fatal(closes)
			}
			switch mode {
			case "complete", "user-selection":
				if err != nil || !result.Complete || !result.Observation.Complete ||
					result.Scanned != 6 ||
					len(result.Accounts) != 4 {
					t.Fatal(result, err)
				}
			case "scan-limit":
				if err != nil || result.Complete || !result.ScanLimitReached ||
					result.MatchLimitReached ||
					result.Scanned != 2 ||
					len(result.Accounts) != 1 ||
					pages != 1 {
					t.Fatal(result, err)
				}
			case "match-limit":
				if err != nil || result.Complete || !result.MatchLimitReached ||
					result.ScanLimitReached ||
					result.Scanned != 2 ||
					len(result.Accounts) != 1 ||
					len(result.Observation.Objects) != 3 ||
					pages != 1 {
					t.Fatal(result, err)
				}
			case "unknown", "wrong-class":
				if !errors.Is(err, admodel.ErrAccountStateUnreadable) || result.Complete ||
					!result.Observation.Complete ||
					len(result.Unknown) != 2 ||
					len(result.Accounts) != 4 {
					t.Fatal(result, err)
				}
			default:
				if !errors.Is(err, denied) || result.Complete || result.Observation.Complete ||
					len(result.Accounts) == 0 {
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
			client := InternalObjectTestClient(
				t,
				nil,
				func(_ context.Context, options admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					searches++
					if mode == "computer" &&
						!strings.Contains(options.Filter, "(objectClass=computer)") {
						t.Fatal(options)
					}
					if mode == "lds" &&
						!strings.Contains(options.Filter, "(objectClass=msDS-BindableObject)") {
						t.Fatal(options)
					}
					return InternalObjectTestCursor(), nil
				},
				func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					t.Fatal("write")
					return admodel.InternalLdapWriteAttempt{}
				},
			)
			if mode == "gc" {
				(*adengine.InternalClientConfigPointer(client)).Endpoint.Port = 3268
			}
			if mode == "lds" {
				session := adengine.InternalClientSession(client).(InternalObjectWriteTestSession)
				session.InternalRead = func(context.Context, []string) (map[string][][]byte, error) {
					return InternalIdentityTestRoot(admodel.CapabilityADLDS), nil
				}
				(*adengine.InternalClientSessionPointer(client)) = session
			}
			query := admodel.AccountStateQuery{Condition: admodel.AccountDisabled}
			if mode == "missing-partition" {
				query.Search.Base = "DC=missing"
			}
			if mode == "computer" {
				query.Kind = admodel.AccountStateComputers
			}
			result, err := adservice_accounts.New(client).
				SearchAccountState(context.Background(), query)
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
		InternalClasses   []string
		InternalKind      admodel.DirectoryType
		InternalSelection admodel.AccountStateKind
		InternalValid     bool
	}{
		{[]string{"user", "computer"}, admodel.DirectoryADDS, admodel.AccountStateComputers, true},
		{[]string{"user", "computer", "msDS-GroupManagedServiceAccount"}, admodel.DirectoryADDS, admodel.AccountStateAll, true},
		{[]string{"inetOrgPerson"}, admodel.DirectoryADLDS, admodel.AccountStateUsers, true},
		{[]string{"msDS-BindableObject", "customPrincipal"}, admodel.DirectoryADLDS, admodel.AccountStateAll, true},
		{[]string{"group"}, admodel.DirectoryADDS, admodel.AccountStateAll, false},
		{[]string{"user", "computer"}, admodel.DirectoryADDS, admodel.AccountStateUsers, false},
		{[]string{"msDS-BindableObject"}, admodel.DirectoryADDS, admodel.AccountStateAll, false},
	} {
		object := InternalAccountTestEntry(514)
		object.Attributes["objectclass"] = nil
		for _, class := range tc.InternalClasses {
			object.Attributes["objectclass"] = append(
				object.Attributes["objectclass"],
				[]byte(class),
			)
		}
		object.Attributes["msds-useraccountdisabled"] = [][]byte{[]byte("TRUE")}
		match, err := admodel.InternalMatchAccountState(
			object,
			tc.InternalKind,
			admodel.AccountStateQuery{
				Condition: admodel.AccountDisabled,
				Kind:      tc.InternalSelection,
			},
		)
		if (err == nil) != tc.InternalValid || (tc.InternalValid && !match) {
			t.Fatal(tc, match, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closes := 0
	result := admodel.AccountStateSearchResult{Directory: admodel.DirectoryADDS}
	err := admodel.InternalCollectAccountState(
		ctx,
		InternalTestSearchCursor{
			InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
				cancel()
				return []admodel.Object{InternalAccountTestEntry(514)}, false, nil
			},
			InternalFinish: func() error { closes++; return nil },
		},
		admodel.SearchOptions{PageSize: 1},
		admodel.AccountStateQuery{Condition: admodel.AccountDisabled, ScanLimit: 10},
		&result,
	)
	if !errors.Is(err, context.Canceled) || result.Complete || result.Scanned != 0 ||
		len(result.Observation.Objects) != 1 ||
		closes != 1 {
		t.Fatal(result, err, closes)
	}
}

package activedirectory

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func identityTestRoot(kind string) map[string][][]byte {
	return map[string][][]byte{
		"supportedcapabilities": {[]byte(kind)}, "defaultnamingcontext": {[]byte("DC=example")},
		"namingcontexts": {[]byte("DC=example"), []byte("CN=Configuration,DC=example"), []byte("CN=Schema,CN=Configuration,DC=example"), []byte("DC=app")},
	}
}

func TestIdentityConstructorsAndDistinguishedNames(t *testing.T) {
	for _, dn := range []string{`CN=Jörg\, 李,OU=People,DC=example`, `CN=J\c3\b6rg\2c 李,DC=example`, `CN=\ leading\ ,DC=example`, `CN=Alice+UID=42,DC=example`, `1.2.3=#040200ff,DC=example`, `CN=,DC=example`} {
		identity, err := IdentityByDN(dn)
		if err != nil || identity.Form() != IdentityFormDN || identity.String() != dn {
			t.Fatalf("DN %q: %#v %v", dn, identity, err)
		}
	}
	for _, dn := range []string{"", "CN=x\x00,DC=example", "CN=\xff", `CN=x,`, `,CN=x`, `CN=x,,DC=e`, `CN=x\`, `CN=\q`, `CN=\ff`, `CN= leading`, `CN=trailing `, `CN="quoted"`, `LDAP://CN=x`, `<GUID=1>`, `CN=#01z2`, `CN;binary=x`, `CN=x+`} {
		if _, err := IdentityByDN(dn); !errors.Is(err, ErrInvalidIdentity) {
			t.Fatalf("accepted DN %q: %v", dn, err)
		}
	}
	a, _ := parseIdentityDN(`CN=Jörg\, 李+UID=42,DC=example`)
	b, _ := parseIdentityDN(`uid=42+cn=J\c3\b6rg\2c 李,dc=EXAMPLE`)
	if !sameIdentityDN(a, b) {
		t.Fatal("escaped Unicode or multivalued RDN comparison differs")
	}
	for _, name := range []string{"", `EXAMPLE\alice`, "alice@example.test", "alice/other", "nul\x00"} {
		if _, err := IdentityByAccountName(name); err == nil {
			t.Fatalf("accepted account identity %q", name)
		}
	}
	account, err := IdentityByAccountName("李*)(objectClass=*)")
	if err != nil {
		t.Fatal(err)
	}
	query := identitySearch(account, "DC=example", ResolveIdentityOptions{Target: IdentityTargetAccount})
	if query.Filter != `(&(objectSid=*)(sAMAccountName=李\2a\29\28objectClass=\2a\29))` {
		t.Fatal(query.Filter)
	}
}

func TestIdentityOperationFormsAndBinaryFilters(t *testing.T) {
	guid, err := IdentityByGUID("00112233-4455-6677-8899-aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	sid, err := IdentityBySID("S-1-5-21-42")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		identity Identity
		filter   string
	}{
		{guid, `(objectGUID=\33\22\11\00\55\44\77\66\88\99\aa\bb\cc\dd\ee\ff)`},
		{sid, `(&(objectSid=*)(objectSid=\01\02\00\00\00\00\00\05\15\00\00\00\2a\00\00\00))`},
	} {
		options := ResolveIdentityOptions{}
		if tc.identity.Form() == IdentityFormSID {
			options.Target = IdentityTargetAccount
		}
		query := identitySearch(tc.identity, "DC=example", options)
		if query.Filter != tc.filter || query.Base != "DC=example" || query.Scope != ScopeSubtree || query.ResultLimit != 2 {
			t.Fatalf("%+v", query)
		}
	}
	for _, identity := range []Identity{sid, {form: IdentityFormAccountName, value: "alice"}} {
		if !errors.Is(validateIdentityOperation(identity, ResolveIdentityOptions{}), ErrUnsupportedIdentity) {
			t.Fatal("object operation accepted an account-only form")
		}
	}
	if !errors.Is(validateIdentityOperation(Identity{}, ResolveIdentityOptions{}), ErrInvalidIdentity) {
		t.Fatal("zero identity accepted")
	}
}

func TestResolveIdentityNamingContextScope(t *testing.T) {
	for _, tc := range []struct {
		name, dn, partition, configured, kind string
		want                                  error
		base                                  string
	}{
		{"escaped Unicode", `CN=Jörg\, 李,DC=example`, "", "", CapabilityActiveDirectory, nil, `CN=Jörg\, 李,DC=example`},
		{"infer schema", "CN=thing,CN=Schema,CN=Configuration,DC=example", "", "", CapabilityActiveDirectory, nil, "CN=thing,CN=Schema,CN=Configuration,DC=example"},
		{"schema is separate", "CN=thing,CN=Schema,CN=Configuration,DC=example", "CN=Configuration,DC=example", "", CapabilityActiveDirectory, ErrIdentityScope, ""},
		{"other domain", "CN=thing,DC=else", "", "", CapabilityActiveDirectory, ErrIdentityScope, ""},
		{"escaped comma is not suffix", `CN=x\,DC=example,DC=else`, "DC=example", "", CapabilityActiveDirectory, ErrIdentityScope, ""},
		{"configured partition", "CN=thing,DC=app", "", "DC=example", CapabilityActiveDirectory, ErrIdentityScope, ""},
		{"explicit override", "CN=thing,DC=app", "DC=app", "DC=example", CapabilityActiveDirectory, nil, "CN=thing,DC=app"},
		{"non NC", "CN=thing,DC=example", "OU=People,DC=example", "", CapabilityActiveDirectory, ErrIdentityScope, ""},
		{"LDS explicit DN", "CN=thing,DC=app", "", "", CapabilityADLDS, nil, "CN=thing,DC=app"},
		{"unknown capability", "CN=thing,DC=example", "", "", "vendor", ErrUnsupportedDirectory, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := newClient(Config{Endpoint: Endpoint{Host: "dc.example"}, Timeout: time.Second, Partition: tc.configured}, testSession{
				read: func(context.Context, []string) (map[string][][]byte, error) { return identityTestRoot(tc.kind), nil },
				search: func(_ context.Context, query SearchOptions) (searchCursor, error) {
					calls++
					if query.Base != tc.base || query.Scope != ScopeBase {
						t.Fatalf("%+v", query)
					}
					return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) {
						return []Object{{DistinguishedName: tc.dn}}, true, nil
					}, finish: func() error { return nil }}, nil
				}, finish: func() error { return nil },
			})
			defer client.Close()
			identity, err := IdentityByDN(tc.dn)
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.ResolveIdentity(context.Background(), identity, ResolveIdentityOptions{Partition: tc.partition})
			if !errors.Is(err, tc.want) || (tc.want == nil && (!result.Complete || result.Object == nil || calls != 1 || result.Source.Host != "dc.example")) || (tc.want != nil && calls != 0) {
				t.Fatalf("%+v %v calls=%d", result, err, calls)
			}
		})
	}
}

func TestResolveIdentityNeverSelectsAmbiguousOrPartialMatches(t *testing.T) {
	permission := &LDAPError{Operation: "search", Code: 50, Diagnostic: "private permission diagnostic", MatchedDN: "DC=example"}
	cleanup := errors.New("injected cursor cleanup failure")
	identity, _ := IdentityByAccountName("alice")
	for _, tc := range []struct {
		name                        string
		count                       int
		complete                    bool
		searchErr, cleanupErr, want error
	}{
		{"unique", 1, true, nil, nil, nil}, {"missing", 0, true, nil, nil, ErrDirectoryObjectNotFound},
		{"ambiguous bounded", 2, false, nil, nil, ErrAmbiguousIdentity}, {"partial permission", 1, false, permission, nil, permission},
		{"cleanup", 1, true, nil, cleanup, cleanup}, {"ambiguous with native failure", 2, false, permission, nil, ErrAmbiguousIdentity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			closed := 0
			client := newClient(Config{Timeout: time.Second}, testSession{
				read: func(context.Context, []string) (map[string][][]byte, error) {
					return identityTestRoot(CapabilityActiveDirectory), nil
				},
				search: func(_ context.Context, query SearchOptions) (searchCursor, error) {
					if query.Base != "DC=example" || query.Filter != "(&(objectSid=*)(sAMAccountName=alice))" {
						t.Fatal(query)
					}
					return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) {
						objects := make([]Object, tc.count)
						for i := range objects {
							objects[i].DistinguishedName = "CN=alice,DC=example"
						}
						return objects, tc.complete, tc.searchErr
					}, finish: func() error { closed++; return tc.cleanupErr }}, nil
				}, finish: func() error { return nil },
			})
			defer client.Close()
			result, err := client.ResolveIdentity(context.Background(), identity, ResolveIdentityOptions{Target: IdentityTargetAccount})
			if !errors.Is(err, tc.want) || len(result.Candidates) != tc.count || closed != 1 || (tc.want != nil && (result.Object != nil || result.Complete)) {
				t.Fatalf("%+v %v closed=%d", result, err, closed)
			}
			if tc.searchErr != nil {
				var native *LDAPError
				if !errors.As(err, &native) || native != permission {
					t.Fatal("native diagnostics lost")
				}
			}
		})
	}
}

func TestResolveIdentityRejectsCapabilityAndReturnedScope(t *testing.T) {
	identity, _ := IdentityByAccountName("alice")
	client := newClient(Config{Timeout: time.Second}, testSession{read: func(context.Context, []string) (map[string][][]byte, error) {
		return identityTestRoot(CapabilityADLDS), nil
	}, finish: func() error { return nil }})
	defer client.Close()
	if _, err := client.ResolveIdentity(context.Background(), identity, ResolveIdentityOptions{Target: IdentityTargetAccount}); !errors.Is(err, ErrUnsupportedDirectory) {
		t.Fatal(err)
	}
	guid, _ := IdentityByGUID("00112233-4455-6677-8899-aabbccddeeff")
	for _, dn := range []string{"CN=x,DC=else", "CN=x,CN=Schema,CN=Configuration,DC=example", "not-a-dn"} {
		c := newClient(Config{Timeout: time.Second}, testSession{read: func(context.Context, []string) (map[string][][]byte, error) {
			return identityTestRoot(CapabilityActiveDirectory), nil
		},
			search: func(context.Context, SearchOptions) (searchCursor, error) {
				return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) {
					return []Object{{DistinguishedName: dn}}, true, nil
				}, finish: func() error { return nil }}, nil
			}, finish: func() error { return nil }})
		result, err := c.ResolveIdentity(context.Background(), guid, ResolveIdentityOptions{})
		if err == nil || result.Object != nil || result.Complete {
			t.Fatalf("accepted %q: %+v %v", dn, result, err)
		}
		c.Close()
	}
	root := RootDSE{NamingContexts: []string{"DC=app"}, SupportedCapabilities: []string{CapabilityADLDS}}
	if _, _, err := identityPartition(guid, "", root); !errors.Is(err, ErrNoDefaultPartition) {
		t.Fatal(err)
	}
}

func FuzzIdentityDistinguishedName(f *testing.F) {
	for _, seed := range []string{`CN=Jörg\, 李,DC=example`, `CN=x+UID=42,DC=example`, `CN=\00,DC=example`, `CN=x\`, ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		identity, err := IdentityByDN(value)
		if err != nil {
			return
		}
		if identity.String() != value {
			t.Fatal("wire identity changed")
		}
		base, err := parseIdentityDN(value)
		if err != nil {
			t.Fatal(err)
		}
		child, err := parseIdentityDN("CN=fuzz," + value)
		if err != nil || !identityWithin(child, base) || !reflect.DeepEqual(child[1:], base) {
			t.Fatal("parsed DN scope lost")
		}
		if strings.ContainsRune(value, 0) {
			t.Fatal("literal NUL accepted")
		}
	})
}

package acceptance

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func InternalIdentityTestRoot(kind string) map[string][][]byte {
	return map[string][][]byte{
		"supportedcapabilities": {[]byte(kind)},
		"defaultnamingcontext":  {[]byte("DC=example")},
		"namingcontexts": {
			[]byte("DC=example"),
			[]byte("CN=Configuration,DC=example"),
			[]byte("CN=Schema,CN=Configuration,DC=example"),
			[]byte("DC=app"),
		},
	}
}

func TestIdentityConstructorsAndDistinguishedNames(t *testing.T) {
	for _, dn := range []string{`CN=Jörg\, 李,OU=People,DC=example`, `CN=J\c3\b6rg\2c 李,DC=example`, `CN=\ leading\ ,DC=example`, `CN=Alice+UID=42,DC=example`, `1.2.3=#040200ff,DC=example`, `CN=,DC=example`} {
		identity, err := admodel.IdentityByDN(dn)
		if err != nil || identity.Form() != admodel.IdentityFormDN || identity.String() != dn {
			t.Fatalf("DN %q: %#v %v", dn, identity, err)
		}
	}
	for _, dn := range []string{"", "CN=x\x00,DC=example", "CN=\xff", `CN=x,`, `,CN=x`, `CN=x,,DC=e`, `CN=x\`, `CN=\q`, `CN=\ff`, `CN= leading`, `CN=trailing `, `CN="quoted"`, `LDAP://CN=x`, `<GUID=1>`, `CN=#01z2`, `CN;binary=x`, `CN=x+`} {
		if _, err := admodel.IdentityByDN(dn); !errors.Is(err, admodel.ErrInvalidIdentity) {
			t.Fatalf("accepted DN %q: %v", dn, err)
		}
	}
	a, _ := admodel.InternalParseIdentityDN(`CN=Jörg\, 李+UID=42,DC=example`)
	b, _ := admodel.InternalParseIdentityDN(`uid=42+cn=J\c3\b6rg\2c 李,dc=EXAMPLE`)
	if !admodel.InternalSameIdentityDN(a, b) {
		t.Fatal("escaped Unicode or multivalued RDN comparison differs")
	}
	for _, name := range []string{"", `EXAMPLE\alice`, "alice@example.test", "alice/other", "nul\x00"} {
		if _, err := admodel.IdentityByAccountName(name); err == nil {
			t.Fatalf("accepted account identity %q", name)
		}
	}
	account, err := admodel.IdentityByAccountName("李*)(objectClass=*)")
	if err != nil {
		t.Fatal(err)
	}
	query := admodel.InternalIdentitySearch(
		account,
		"DC=example",
		admodel.ResolveIdentityOptions{Target: admodel.IdentityTargetAccount},
	)
	if query.Filter != `(&(objectSid=*)(sAMAccountName=李\2a\29\28objectClass=\2a\29))` {
		t.Fatal(query.Filter)
	}
}

func TestIdentityOperationFormsAndBinaryFilters(t *testing.T) {
	guid, err := admodel.IdentityByGUID("00112233-4455-6677-8899-aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	sid, err := admodel.IdentityBySID("S-1-5-21-42")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		InternalIdentity admodel.Identity
		InternalFilter   string
	}{
		{guid, `(objectGUID=\33\22\11\00\55\44\77\66\88\99\aa\bb\cc\dd\ee\ff)`},
		{sid, `(&(objectSid=*)(objectSid=\01\02\00\00\00\00\00\05\15\00\00\00\2a\00\00\00))`},
	} {
		options := admodel.ResolveIdentityOptions{}
		if tc.InternalIdentity.Form() == admodel.IdentityFormSID {
			options.Target = admodel.IdentityTargetAccount
		}
		query := admodel.InternalIdentitySearch(tc.InternalIdentity, "DC=example", options)
		if query.Filter != tc.InternalFilter || query.Base != "DC=example" ||
			query.Scope != admodel.ScopeSubtree ||
			query.ResultLimit != 2 {
			t.Fatalf("%+v", query)
		}
	}
	for _, identity := range []admodel.Identity{sid, admodel.InternalIdentityFromFields(admodel.InternalIdentityFields{Form: admodel.IdentityFormAccountName, Value: "alice"})} {
		if !errors.Is(
			admodel.InternalValidateIdentityOperation(identity, admodel.ResolveIdentityOptions{}),
			admodel.ErrUnsupportedIdentity,
		) {
			t.Fatal("object operation accepted an account-only form")
		}
	}
	if !errors.Is(
		admodel.InternalValidateIdentityOperation(
			admodel.Identity{},
			admodel.ResolveIdentityOptions{},
		),
		admodel.ErrInvalidIdentity,
	) {
		t.Fatal("zero identity accepted")
	}
}

func TestResolveIdentityNamingContextScope(t *testing.T) {
	for _, tc := range []struct {
		InternalName, InternalDn, InternalPartition, InternalConfigured, InternalKind string
		InternalWant                                                                  error
		InternalBase                                                                  string
	}{
		{"escaped Unicode", `CN=Jörg\, 李,DC=example`, "", "", admodel.CapabilityActiveDirectory, nil, `CN=Jörg\, 李,DC=example`},
		{"infer schema", "CN=thing,CN=Schema,CN=Configuration,DC=example", "", "", admodel.CapabilityActiveDirectory, nil, "CN=thing,CN=Schema,CN=Configuration,DC=example"},
		{"schema is separate", "CN=thing,CN=Schema,CN=Configuration,DC=example", "CN=Configuration,DC=example", "", admodel.CapabilityActiveDirectory, admodel.ErrIdentityScope, ""},
		{"other domain", "CN=thing,DC=else", "", "", admodel.CapabilityActiveDirectory, admodel.ErrIdentityScope, ""},
		{"escaped comma is not suffix", `CN=x\,DC=example,DC=else`, "DC=example", "", admodel.CapabilityActiveDirectory, admodel.ErrIdentityScope, ""},
		{"configured partition", "CN=thing,DC=app", "", "DC=example", admodel.CapabilityActiveDirectory, admodel.ErrIdentityScope, ""},
		{"explicit override", "CN=thing,DC=app", "DC=app", "DC=example", admodel.CapabilityActiveDirectory, nil, "CN=thing,DC=app"},
		{"non NC", "CN=thing,DC=example", "OU=People,DC=example", "", admodel.CapabilityActiveDirectory, admodel.ErrIdentityScope, ""},
		{"LDS explicit DN", "CN=thing,DC=app", "", "", admodel.CapabilityADLDS, nil, "CN=thing,DC=app"},
		{"unknown capability", "CN=thing,DC=example", "", "", "vendor", admodel.ErrUnsupportedDirectory, ""},
	} {
		t.Run(tc.InternalName, func(t *testing.T) {
			calls := 0
			client := adengine.InternalNewClient(
				admodel.Config{
					Endpoint:  admodel.Endpoint{Host: "dc.example"},
					Timeout:   time.Second,
					Partition: tc.InternalConfigured,
				},
				InternalTestSession{
					InternalRead: func(context.Context, []string) (map[string][][]byte, error) {
						return InternalIdentityTestRoot(tc.InternalKind), nil
					},
					InternalSearch: func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
						calls++
						if query.Base != tc.InternalBase || query.Scope != admodel.ScopeBase {
							t.Fatalf("%+v", query)
						}
						return InternalTestSearchCursor{
							InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
								return []admodel.Object{
									{DistinguishedName: tc.InternalDn},
								}, true, nil
							},
							InternalFinish: func() error { return nil },
						}, nil
					},
					InternalFinish: func() error { return nil },
				},
			)
			defer client.Close()
			identity, err := admodel.IdentityByDN(tc.InternalDn)
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.ResolveIdentity(
				context.Background(),
				identity,
				admodel.ResolveIdentityOptions{Partition: tc.InternalPartition},
			)
			if !errors.Is(err, tc.InternalWant) ||
				(tc.InternalWant == nil && (!result.Complete || result.Object == nil || calls != 1 || result.Source.Host != "dc.example")) ||
				(tc.InternalWant != nil && calls != 0) {
				t.Fatalf("%+v %v calls=%d", result, err, calls)
			}
		})
	}
}

func TestResolveIdentityNeverSelectsAmbiguousOrPartialMatches(t *testing.T) {
	permission := &admodel.LDAPError{
		Operation:  "search",
		Code:       50,
		Diagnostic: "private permission diagnostic",
		MatchedDN:  "DC=example",
	}
	cleanup := errors.New("injected cursor cleanup failure")
	identity, _ := admodel.IdentityByAccountName("alice")
	for _, tc := range []struct {
		InternalName                                        string
		InternalCount                                       int
		InternalComplete                                    bool
		InternalSearchErr, InternalCleanupErr, InternalWant error
	}{
		{"unique", 1, true, nil, nil, nil},
		{"missing", 0, true, nil, nil, admodel.ErrDirectoryObjectNotFound},
		{"ambiguous bounded", 2, false, nil, nil, admodel.ErrAmbiguousIdentity},
		{"partial permission", 1, false, permission, nil, permission},
		{"cleanup", 1, true, nil, cleanup, cleanup},
		{"ambiguous with native failure", 2, false, permission, nil, admodel.ErrAmbiguousIdentity},
	} {
		t.Run(tc.InternalName, func(t *testing.T) {
			closed := 0
			client := adengine.InternalNewClient(
				admodel.Config{Timeout: time.Second},
				InternalTestSession{
					InternalRead: func(context.Context, []string) (map[string][][]byte, error) {
						return InternalIdentityTestRoot(admodel.CapabilityActiveDirectory), nil
					},
					InternalSearch: func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
						if query.Base != "DC=example" ||
							query.Filter != "(&(objectSid=*)(sAMAccountName=alice))" {
							t.Fatal(query)
						}
						return InternalTestSearchCursor{
							InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
								objects := make([]admodel.Object, tc.InternalCount)
								for i := range objects {
									objects[i].DistinguishedName = "CN=alice,DC=example"
								}
								return objects, tc.InternalComplete, tc.InternalSearchErr
							},
							InternalFinish: func() error { closed++; return tc.InternalCleanupErr },
						}, nil
					},
					InternalFinish: func() error { return nil },
				},
			)
			defer client.Close()
			result, err := client.ResolveIdentity(
				context.Background(),
				identity,
				admodel.ResolveIdentityOptions{Target: admodel.IdentityTargetAccount},
			)
			if !errors.Is(err, tc.InternalWant) || len(result.Candidates) != tc.InternalCount ||
				closed != 1 ||
				(tc.InternalWant != nil && (result.Object != nil || result.Complete)) {
				t.Fatalf("%+v %v closed=%d", result, err, closed)
			}
			if tc.InternalSearchErr != nil {
				var native *admodel.LDAPError
				if !errors.As(err, &native) || native != permission {
					t.Fatal("native diagnostics lost")
				}
			}
		})
	}
}

func TestResolveIdentityRejectsCapabilityAndReturnedScope(t *testing.T) {
	identity, _ := admodel.IdentityByAccountName("alice")
	client := adengine.InternalNewClient(
		admodel.Config{Timeout: time.Second},
		InternalTestSession{
			InternalRead: func(context.Context, []string) (map[string][][]byte, error) {
				return InternalIdentityTestRoot(admodel.CapabilityADLDS), nil
			},
			InternalFinish: func() error { return nil },
		},
	)
	defer client.Close()
	if _, err := client.ResolveIdentity(
		context.Background(),
		identity,
		admodel.ResolveIdentityOptions{Target: admodel.IdentityTargetAccount},
	); !errors.Is(
		err,
		admodel.ErrUnsupportedDirectory,
	) {
		t.Fatal(err)
	}
	guid, _ := admodel.IdentityByGUID("00112233-4455-6677-8899-aabbccddeeff")
	for _, dn := range []string{"CN=x,DC=else", "CN=x,CN=Schema,CN=Configuration,DC=example", "not-a-dn"} {
		c := adengine.InternalNewClient(admodel.Config{Timeout: time.Second}, InternalTestSession{
			InternalRead: func(context.Context, []string) (map[string][][]byte, error) {
				return InternalIdentityTestRoot(admodel.CapabilityActiveDirectory), nil
			},
			InternalSearch: func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				return InternalTestSearchCursor{
					InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
						return []admodel.Object{{DistinguishedName: dn}}, true, nil
					},
					InternalFinish: func() error { return nil },
				}, nil
			},
			InternalFinish: func() error { return nil },
		})
		result, err := c.ResolveIdentity(
			context.Background(),
			guid,
			admodel.ResolveIdentityOptions{},
		)
		if err == nil || result.Object != nil || result.Complete {
			t.Fatalf("accepted %q: %+v %v", dn, result, err)
		}
		c.Close()
	}
	root := admodel.RootDSE{
		NamingContexts:        []string{"DC=app"},
		SupportedCapabilities: []string{admodel.CapabilityADLDS},
	}
	if _, _, err := admodel.InternalIdentityPartition(
		guid,
		"",
		root,
	); !errors.Is(
		err,
		admodel.ErrNoDefaultPartition,
	) {
		t.Fatal(err)
	}
}

func FuzzIdentityDistinguishedName(f *testing.F) {
	for _, seed := range []string{`CN=Jörg\, 李,DC=example`, `CN=x+UID=42,DC=example`, `CN=\00,DC=example`, `CN=x\`, ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		identity, err := admodel.IdentityByDN(value)
		if err != nil {
			return
		}
		if identity.String() != value {
			t.Fatal("wire identity changed")
		}
		base, err := admodel.InternalParseIdentityDN(value)
		if err != nil {
			t.Fatal(err)
		}
		child, err := admodel.InternalParseIdentityDN("CN=fuzz," + value)
		if err != nil || !admodel.InternalIdentityWithin(child, base) ||
			!reflect.DeepEqual(child[1:], base) {
			t.Fatal("parsed DN scope lost")
		}
		if strings.ContainsRune(value, 0) {
			t.Fatal("literal NUL accepted")
		}
	})
}

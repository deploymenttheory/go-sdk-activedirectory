package acceptance

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_memberships "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/memberships"
)

func InternalGroupMemberDN(t *testing.T, dn string) admodel.Identity {
	t.Helper()
	identity, err := admodel.IdentityByDN(dn)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func TestGroupMembershipAtomicModesAndReferences(t *testing.T) {
	foreign := InternalGroupMemberDN(t, `CN=Jörg\, Admin,DC=foreign`)
	guid, _ := admodel.IdentityByGUID(InternalObjectTestGUID().String())
	sid, _ := admodel.IdentityBySID("S-1-5-21-42")
	sam, _ := admodel.IdentityByAccountName("nested")
	for _, remove := range []bool{false, true} {
		for _, strict := range []bool{false, true} {
			t.Run(fmt.Sprintf("remove=%t/strict=%t", remove, strict), func(t *testing.T) {
				writes, searches := 0, 0
				client := InternalObjectTestClient(
					t,
					[]string{admodel.InternalGroupPermissiveModify},
					func(_ context.Context, options admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
						searches++
						if searches == 2 && !strings.Contains(options.Filter, "nested") {
							t.Fatal(options)
						}
						return InternalObjectTestCursor(InternalGroupTestEntry(0x80000002)), nil
					},
					func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
						writes++
						if request.InternalOperation != admodel.InternalLdapWriteModify ||
							request.InternalDn != admodel.InternalObjectGUIDTarget(
								InternalObjectTestGUID(),
							) ||
							len(request.InternalModifications) != 1 {
							t.Fatal(request)
						}
						mod := request.InternalModifications[0]
						wantOp := uint32(0)
						if remove {
							wantOp = 1
						}
						want := [][]byte{
							[]byte(foreign.String()),
							[]byte("<GUID=33221100554477668899aabbccddeeff>"),
							[]byte("<SID=0102000000000005150000002a000000>"),
							[]byte("<GUID=33221100554477668899aabbccddeeff>"),
							[]byte(foreign.String()),
						}
						if mod.InternalOperation != wantOp || mod.InternalAttribute != "member" ||
							!reflect.DeepEqual(mod.InternalValues, want) {
							t.Fatal(mod)
						}
						if strict && len(request.InternalControls) != 0 {
							t.Fatal(request.InternalControls)
						}
						if !strict &&
							(len(request.InternalControls) != 1 || request.InternalControls[0].InternalOid != admodel.InternalGroupPermissiveModify || !request.InternalControls[0].InternalCritical || len(request.InternalControls[0].InternalValue) != 0) {
							t.Fatal(request.InternalControls)
						}
						return admodel.InternalLdapWriteAttempt{
							State: admodel.InternalLdapWriteAccepted,
						}
					},
				)
				mode := admodel.GroupMembershipPermissive
				if strict {
					mode = admodel.GroupMembershipStrict
				}
				members := []admodel.Identity{foreign, guid, sid, sam, foreign}
				var result admodel.GroupMembershipMutationResult
				var err error
				if remove {
					result, err = adservice_memberships.New(client).
						RemoveGroupMembers(context.Background(), admodel.RemoveGroupMembersRequest{Identity: InternalObjectTestIdentity(), Members: members, Mode: mode})
				} else {
					result, err = adservice_memberships.New(client).
						AddGroupMembers(context.Background(), admodel.AddGroupMembersRequest{Identity: InternalObjectTestIdentity(), Members: members, Mode: mode})
				}
				if err != nil || writes != 1 || searches != 3 ||
					result.Mutation.State != admodel.ObjectWriteAccepted ||
					result.Mutation.Verified ||
					!result.Mutation.ReadbackComplete ||
					result.Members[3].Resolution == nil {
					t.Fatal(result, err, writes, searches)
				}
			})
		}
	}
}

func TestGroupMembershipFailureNeverSplitsOrReplays(t *testing.T) {
	for _, tc := range []struct {
		InternalName  string
		InternalState admodel.InternalLdapWriteState
		InternalCause error
		InternalWant  admodel.ObjectWriteState
	}{
		{"constraint", admodel.InternalLdapWriteRejected, &admodel.LDAPError{Code: 19}, admodel.ObjectWriteRejected},
		{"exists", admodel.InternalLdapWriteRejected, &admodel.LDAPError{Code: 20}, admodel.ObjectWriteRejected},
		{"missing", admodel.InternalLdapWriteRejected, &admodel.LDAPError{Code: 16}, admodel.ObjectWriteRejected},
		{"permission", admodel.InternalLdapWriteRejected, &admodel.LDAPError{Code: 50}, admodel.ObjectWriteRejected},
		{"uncertain", admodel.InternalLdapWriteUncertain, context.DeadlineExceeded, admodel.ObjectWriteUncertain},
		{"accepted-cleanup-failed", admodel.InternalLdapWriteAccepted, errors.New("cleanup"), admodel.ObjectWriteAccepted},
	} {
		t.Run(tc.InternalName, func(t *testing.T) {
			writes, reads := 0, 0
			client := InternalObjectTestClient(
				t,
				nil,
				func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					reads++
					return InternalObjectTestCursor(InternalGroupTestEntry(2)), nil
				},
				func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					writes++
					return admodel.InternalLdapWriteAttempt{
						State: tc.InternalState,
						Err:   tc.InternalCause,
					}
				},
			)
			result, err := adservice_memberships.New(client).
				AddGroupMembers(context.Background(), admodel.AddGroupMembersRequest{Identity: InternalObjectTestIdentity(), Members: []admodel.Identity{InternalObjectTestIdentity(), InternalGroupMemberDN(t, "CN=second,DC=foreign")}, Mode: admodel.GroupMembershipStrict})
			if !errors.Is(err, tc.InternalCause) || writes != 1 || reads != 1 ||
				result.Mutation.State != tc.InternalWant ||
				result.Mutation.Verified {
				t.Fatal(result, err, writes, reads)
			}
			if tc.InternalState == admodel.InternalLdapWriteUncertain &&
				!errors.Is(err, admodel.ErrObjectWriteUncertain) {
				t.Fatal(err)
			}
		})
	}
}

func TestGroupMembershipTTLAndCapabilityGuards(t *testing.T) {
	for _, mode := range []string{"ttl", "no-ttl-control", "no-permissive", "not-group", "ambiguous-member", "assertion"} {
		t.Run(mode, func(t *testing.T) {
			controls := []string{
				admodel.InternalGroupLinkTTL,
				admodel.InternalGroupPermissiveModify,
			}
			if mode == "no-ttl-control" {
				controls = []string{admodel.InternalGroupPermissiveModify}
			}
			if mode == "no-permissive" {
				controls = []string{admodel.InternalGroupLinkTTL}
			}
			writes, reads := 0, 0
			client := InternalObjectTestClient(
				t,
				controls,
				func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					reads++
					object := InternalGroupTestEntry(2)
					if mode == "not-group" {
						object.Attributes["objectclass"] = [][]byte{[]byte("user")}
					}
					if mode == "ambiguous-member" && reads == 2 {
						return InternalObjectTestCursor(object, object), nil
					}
					return InternalObjectTestCursor(object), nil
				},
				func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					writes++
					if string(
						request.InternalModifications[0].InternalValues[0],
					) != "<TTL=90,CN=sample,DC=example>" ||
						len(request.InternalControls) != 1 ||
						request.InternalControls[0].InternalOid != admodel.InternalGroupPermissiveModify {
						t.Fatal(request)
					}
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteAccepted,
					}
				},
			)
			ttl := 90 * time.Second
			request := admodel.AddGroupMembersRequest{
				Identity:   InternalObjectTestIdentity(),
				Members:    []admodel.Identity{InternalObjectTestIdentity()},
				TimeToLive: &ttl,
			}
			if mode == "ambiguous-member" {
				sam, _ := admodel.IdentityByAccountName("ambiguous")
				request.Members = []admodel.Identity{sam}
			}
			if mode == "assertion" {
				request.Options.ExpectedVersion = &admodel.ObjectVersion{
					Source:     (*adengine.InternalClientConfigPointer(client)).Endpoint,
					GUID:       InternalObjectTestGUID(),
					USNChanged: 7,
				}
			}
			result, err := adservice_memberships.New(client).
				AddGroupMembers(context.Background(), request)
			if mode == "ttl" {
				if err != nil || writes != 1 ||
					result.Mutation.State != admodel.ObjectWriteAccepted {
					t.Fatal(result, err)
				}
				return
			}
			if err == nil || writes != 0 ||
				result.Mutation.State != admodel.ObjectWriteNotAttempted {
				t.Fatal(result, err)
			}
			if mode == "ambiguous-member" &&
				(result.Members[0].Resolution == nil || len(result.Members[0].Resolution.Candidates) != 2) {
				t.Fatal(result)
			}
		})
	}
}

func TestGroupMembershipRejectsInvalidInputsBeforeConnection(t *testing.T) {
	var client *adengine.Client
	for _, ttl := range []time.Duration{-time.Second, time.Second + 1} {
		_, err := adservice_memberships.New(client).
			AddGroupMembers(context.Background(), admodel.AddGroupMembersRequest{Identity: InternalObjectTestIdentity(), Members: []admodel.Identity{InternalObjectTestIdentity()}, TimeToLive: &ttl})
		if !errors.Is(err, admodel.ErrInvalidGroupMembership) {
			t.Fatal(err)
		}
	}
	for _, members := range [][]admodel.Identity{nil, {{}}, make([]admodel.Identity, admodel.InternalMaxGroupWriteMembers+1)} {
		_, err := adservice_memberships.New(client).
			AddGroupMembers(context.Background(), admodel.AddGroupMembersRequest{Identity: InternalObjectTestIdentity(), Members: members})
		if err == nil || errors.Is(err, admodel.ErrClosed) {
			t.Fatal(err)
		}
	}
}

type InternalGroupMemberTestSession struct {
	InternalTestSession
	InternalMemberRead func(context.Context, string, []string, bool) (map[string][][]byte, error)
}

func (s InternalGroupMemberTestSession) InternalGroupMemberBaseObject(
	ctx context.Context,
	base string,
	properties []string,
	ttl bool,
) (map[string][][]byte, error) {
	return s.InternalMemberRead(ctx, base, properties, ttl)
}

func InternalMemberRangeAttributes(name string, values ...string) map[string][][]byte {
	attrs := map[string][][]byte{
		"objectguid": {InternalObjectTestGUID().Bytes()},
		"usnchanged": {[]byte("7")},
	}
	if name != "" {
		attrs[name] = [][]byte{}
		for _, value := range values {
			attrs[name] = append(attrs[name], []byte(value))
		}
	}
	return attrs
}

func InternalMemberReadClient(
	t *testing.T,
	read func(context.Context, string, []string, bool) (map[string][][]byte, error),
) *adengine.Client {
	t.Helper()
	client := adengine.InternalNewClient(
		admodel.Config{
			Endpoint: admodel.Endpoint{Host: "dc.example", Port: 389},
			Timeout:  time.Second,
		},
		InternalGroupMemberTestSession{InternalTestSession: InternalTestSession{
			InternalRead: func(context.Context, []string) (map[string][][]byte, error) {
				root := InternalIdentityTestRoot(admodel.CapabilityActiveDirectory)
				root["supportedcontrol"] = [][]byte{[]byte(admodel.InternalGroupLinkTTL)}
				return root, nil
			},
			InternalSearch: func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				return InternalObjectTestCursor(InternalGroupTestEntry(2)), nil
			},
			InternalFinish: func() error { return nil },
		}, InternalMemberRead: read},
	)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestGroupMemberLinksRangesBeyondServerThreshold(t *testing.T) {
	reads := 0
	client := InternalMemberReadClient(
		t,
		func(_ context.Context, base string, attrs []string, ttl bool) (map[string][][]byte, error) {
			if base != admodel.InternalObjectGUIDTarget(InternalObjectTestGUID()) || ttl {
				t.Fatal(base, ttl)
			}
			start := reads * 1500
			reads++
			if attrs[0] != fmt.Sprintf("member;range=%d-%d", start, start+1499) {
				t.Fatal(attrs)
			}
			count, name := 1500, fmt.Sprintf("member;range=%d-%d", start, start+1499)
			if reads == 3 {
				count, name = 3, "member;range=3000-*"
			}
			values := make([]string, count)
			for i := range values {
				values[i] = fmt.Sprintf("CN=user%d,DC=example", start+i)
			}
			result := InternalMemberRangeAttributes(name, values...)
			result["member"] = nil
			return result, nil
		},
	)
	result, err := adservice_memberships.New(client).
		GroupMemberLinks(context.Background(), InternalObjectTestIdentity(), admodel.GroupMemberLinksOptions{})
	if err != nil || !result.Complete || !result.AttributeReturned || len(result.Members) != 3003 ||
		len(result.Ranges) != 3 ||
		reads != 3 {
		t.Fatal(len(result.Members), result.Complete, err)
	}
}

func TestGroupMemberLinksPartialFailuresAndBounds(t *testing.T) {
	for _, mode := range []string{"gap", "overlap", "missing-tail", "count", "permission", "changed", "wrong-guid", "range-limit", "value-limit", "byte-limit", "malformed-dn", "conflicting-plain"} {
		t.Run(mode, func(t *testing.T) {
			reads := 0
			client := InternalMemberReadClient(
				t,
				func(_ context.Context, _ string, _ []string, _ bool) (map[string][][]byte, error) {
					reads++
					if reads == 1 {
						return InternalMemberRangeAttributes(
							"member;range=0-0",
							"CN=first,DC=example",
						), nil
					}
					attrs := InternalMemberRangeAttributes(
						"member;range=1-*",
						"CN=second,DC=example",
					)
					switch mode {
					case "gap":
						attrs = InternalMemberRangeAttributes(
							"member;range=2-*",
							"CN=second,DC=example",
						)
					case "overlap":
						attrs = InternalMemberRangeAttributes(
							"member;range=0-*",
							"CN=second,DC=example",
						)
					case "missing-tail":
						attrs = InternalMemberRangeAttributes("")
					case "count":
						attrs = InternalMemberRangeAttributes(
							"member;range=1-3",
							"CN=second,DC=example",
						)
					case "permission":
						return attrs, &admodel.LDAPError{Code: 50}
					case "changed":
						attrs["usnchanged"] = [][]byte{[]byte("8")}
					case "wrong-guid":
						attrs["objectguid"] = [][]byte{make([]byte, 16)}
					case "malformed-dn":
						attrs = InternalMemberRangeAttributes("member;range=1-*", "not a dn")
					case "conflicting-plain":
						attrs["member"] = [][]byte{[]byte("CN=third,DC=example")}
					}
					return attrs, nil
				},
			)
			options := admodel.GroupMemberLinksOptions{}
			switch mode {
			case "range-limit":
				options.MaxRanges = 1
			case "value-limit":
				options.MaxValues = 1
			case "byte-limit":
				options.MaxBytes = 1
			}
			result, err := adservice_memberships.New(client).
				GroupMemberLinks(context.Background(), InternalObjectTestIdentity(), options)
			if err == nil || result.Complete || len(result.Ranges) == 0 ||
				(mode != "byte-limit" && len(result.Members) == 0) ||
				reads > 2 {
				t.Fatal(result, err, reads)
			}
			if strings.HasSuffix(mode, "limit") &&
				(!errors.Is(err, admodel.ErrGroupMembershipLimit) || reads != 1) {
				t.Fatal(err, reads)
			}
			if (mode == "changed" || mode == "wrong-guid") &&
				!errors.Is(err, admodel.ErrGroupMembershipChanged) {
				t.Fatal(err)
			}
		})
	}
}

func TestGroupMemberLinksTTLAndOmission(t *testing.T) {
	for _, mode := range []string{"ttl", "omitted", "empty"} {
		t.Run(mode, func(t *testing.T) {
			client := InternalMemberReadClient(
				t,
				func(_ context.Context, _ string, _ []string, ttl bool) (map[string][][]byte, error) {
					if !ttl {
						t.Fatal("missing TTL control")
					}
					if mode == "omitted" {
						return InternalMemberRangeAttributes(""), nil
					}
					if mode == "empty" {
						return InternalMemberRangeAttributes("member"), nil
					}
					return InternalMemberRangeAttributes(
						"member;range=0-*",
						`<TTL=89,CN=Jörg\, Admin,DC=example>`,
						"CN=permanent,DC=example",
					), nil
				},
			)
			result, err := adservice_memberships.New(client).
				GroupMemberLinks(context.Background(), InternalObjectTestIdentity(), admodel.GroupMemberLinksOptions{IncludeTTL: true})
			if err != nil || !result.Complete || result.AttributeReturned != (mode != "omitted") {
				t.Fatal(result, err)
			}
			if mode == "ttl" &&
				(len(result.Members) != 2 || *result.Members[0].RemainingTTLSeconds != 89 || result.Members[1].RemainingTTLSeconds != nil || result.Members[0].ObservedAt.IsZero()) {
				t.Fatal(result)
			}
		})
	}
}

func FuzzGroupMemberRange(f *testing.F) {
	for _, value := range []string{"member;range=0-0", "member;range=0-*", "member;range=0-18446744073709551615", "member;range=+0-0", "member;range=1-*"} {
		f.Add(value, uint64(0))
	}
	f.Fuzz(func(t *testing.T, name string, start uint64) {
		values, next, terminal, _, err := admodel.InternalGroupMemberRange(
			map[string][][]byte{name: {[]byte("CN=value,DC=example")}},
			start,
		)
		if err == nil && !terminal && (next <= start || next-start != uint64(len(values))) {
			t.Fatal(name, start, next)
		}
	})
}

func TestGroupMemberLinksCancellationAndGlobalCatalog(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reads := 0
	client := InternalMemberReadClient(
		t,
		func(context.Context, string, []string, bool) (map[string][][]byte, error) {
			reads++
			cancel()
			return InternalMemberRangeAttributes("member;range=0-0", "CN=first,DC=example"), nil
		},
	)
	result, err := adservice_memberships.New(client).
		GroupMemberLinks(ctx, InternalObjectTestIdentity(), admodel.GroupMemberLinksOptions{})
	if !errors.Is(err, context.Canceled) || result.Complete || len(result.Members) != 1 ||
		reads != 1 {
		t.Fatal(result, err, reads)
	}
	(*adengine.InternalClientConfigPointer(client)).Endpoint.Port = 3268
	result, err = adservice_memberships.New(client).
		GroupMemberLinks(context.Background(), InternalObjectTestIdentity(), admodel.GroupMemberLinksOptions{})
	if !errors.Is(err, admodel.ErrGroupMembershipTarget) || result.Complete || reads != 1 {
		t.Fatal(result, err, reads)
	}
}

func TestGroupMembershipLDSDirectReferencesAndAccountGuard(t *testing.T) {
	for _, account := range []bool{false, true} {
		t.Run(fmt.Sprint(account), func(t *testing.T) {
			writes := 0
			client := InternalObjectTestClient(
				t,
				nil,
				func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					return InternalObjectTestCursor(InternalGroupTestEntry(2)), nil
				},
				func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					writes++
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteAccepted,
					}
				},
			)
			session := adengine.InternalClientSession(client).(InternalObjectWriteTestSession)
			session.InternalRead = func(context.Context, []string) (map[string][][]byte, error) {
				return InternalIdentityTestRoot(admodel.CapabilityADLDS), nil
			}
			(*adengine.InternalClientSessionPointer(client)) = session
			member := InternalGroupMemberDN(t, "CN=member,DC=example")
			if account {
				member, _ = admodel.IdentityByAccountName("member")
			}
			result, err := adservice_memberships.New(client).
				AddGroupMembers(context.Background(), admodel.AddGroupMembersRequest{Identity: InternalObjectTestIdentity(), Members: []admodel.Identity{member}, Mode: admodel.GroupMembershipStrict})
			if account {
				if !errors.Is(err, admodel.ErrUnsupportedDirectory) || writes != 0 ||
					result.Mutation.State != admodel.ObjectWriteNotAttempted {
					t.Fatal(result, err, writes)
				}
			} else if err != nil || writes != 1 || result.Mutation.State != admodel.ObjectWriteAccepted {
				t.Fatal(result, err, writes)
			}
		})
	}
}

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func groupMemberDN(t *testing.T, dn string) Identity {
	t.Helper()
	identity, err := IdentityByDN(dn)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func TestGroupMembershipAtomicModesAndReferences(t *testing.T) {
	foreign := groupMemberDN(t, `CN=Jörg\, Admin,DC=foreign`)
	guid, _ := IdentityByGUID(objectTestGUID().String())
	sid, _ := IdentityBySID("S-1-5-21-42")
	sam, _ := IdentityByAccountName("nested")
	for _, remove := range []bool{false, true} {
		for _, strict := range []bool{false, true} {
			t.Run(fmt.Sprintf("remove=%t/strict=%t", remove, strict), func(t *testing.T) {
				writes, searches := 0, 0
				client := objectTestClient(t, []string{groupPermissiveModify}, func(_ context.Context, options SearchOptions) (searchCursor, error) {
					searches++
					if searches == 2 && !strings.Contains(options.Filter, "nested") {
						t.Fatal(options)
					}
					return objectTestCursor(groupTestEntry(0x80000002)), nil
				}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
					writes++
					if request.operation != ldapWriteModify || request.dn != objectGUIDTarget(objectTestGUID()) || len(request.modifications) != 1 {
						t.Fatal(request)
					}
					mod := request.modifications[0]
					wantOp := uint32(0)
					if remove {
						wantOp = 1
					}
					want := [][]byte{[]byte(foreign.String()), []byte("<GUID=33221100554477668899aabbccddeeff>"), []byte("<SID=0102000000000005150000002a000000>"), []byte("<GUID=33221100554477668899aabbccddeeff>"), []byte(foreign.String())}
					if mod.operation != wantOp || mod.attribute != "member" || !reflect.DeepEqual(mod.values, want) {
						t.Fatal(mod)
					}
					if strict && len(request.controls) != 0 {
						t.Fatal(request.controls)
					}
					if !strict && (len(request.controls) != 1 || request.controls[0].oid != groupPermissiveModify || !request.controls[0].critical || len(request.controls[0].value) != 0) {
						t.Fatal(request.controls)
					}
					return ldapWriteAttempt{State: ldapWriteAccepted}
				})
				mode := GroupMembershipPermissive
				if strict {
					mode = GroupMembershipStrict
				}
				members := []Identity{foreign, guid, sid, sam, foreign}
				var result GroupMembershipMutationResult
				var err error
				if remove {
					result, err = client.RemoveGroupMembers(context.Background(), RemoveGroupMembersRequest{Identity: objectTestIdentity(), Members: members, Mode: mode})
				} else {
					result, err = client.AddGroupMembers(context.Background(), AddGroupMembersRequest{Identity: objectTestIdentity(), Members: members, Mode: mode})
				}
				if err != nil || writes != 1 || searches != 3 || result.Mutation.State != ObjectWriteAccepted || result.Mutation.Verified || !result.Mutation.ReadbackComplete || result.Members[3].Resolution == nil {
					t.Fatal(result, err, writes, searches)
				}
			})
		}
	}
}

func TestGroupMembershipFailureNeverSplitsOrReplays(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state ldapWriteState
		cause error
		want  ObjectWriteState
	}{
		{"constraint", ldapWriteRejected, &LDAPError{Code: 19}, ObjectWriteRejected},
		{"exists", ldapWriteRejected, &LDAPError{Code: 20}, ObjectWriteRejected},
		{"missing", ldapWriteRejected, &LDAPError{Code: 16}, ObjectWriteRejected},
		{"permission", ldapWriteRejected, &LDAPError{Code: 50}, ObjectWriteRejected},
		{"uncertain", ldapWriteUncertain, context.DeadlineExceeded, ObjectWriteUncertain},
		{"accepted-cleanup-failed", ldapWriteAccepted, errors.New("cleanup"), ObjectWriteAccepted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writes, reads := 0, 0
			client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
				reads++
				return objectTestCursor(groupTestEntry(2)), nil
			}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
				writes++
				return ldapWriteAttempt{State: tc.state, Err: tc.cause}
			})
			result, err := client.AddGroupMembers(context.Background(), AddGroupMembersRequest{Identity: objectTestIdentity(), Members: []Identity{objectTestIdentity(), groupMemberDN(t, "CN=second,DC=foreign")}, Mode: GroupMembershipStrict})
			if !errors.Is(err, tc.cause) || writes != 1 || reads != 1 || result.Mutation.State != tc.want || result.Mutation.Verified {
				t.Fatal(result, err, writes, reads)
			}
			if tc.state == ldapWriteUncertain && !errors.Is(err, ErrObjectWriteUncertain) {
				t.Fatal(err)
			}
		})
	}
}

func TestGroupMembershipTTLAndCapabilityGuards(t *testing.T) {
	for _, mode := range []string{"ttl", "no-ttl-control", "no-permissive", "not-group", "ambiguous-member", "assertion"} {
		t.Run(mode, func(t *testing.T) {
			controls := []string{groupLinkTTL, groupPermissiveModify}
			if mode == "no-ttl-control" {
				controls = []string{groupPermissiveModify}
			}
			if mode == "no-permissive" {
				controls = []string{groupLinkTTL}
			}
			writes, reads := 0, 0
			client := objectTestClient(t, controls, func(context.Context, SearchOptions) (searchCursor, error) {
				reads++
				object := groupTestEntry(2)
				if mode == "not-group" {
					object.Attributes["objectclass"] = [][]byte{[]byte("user")}
				}
				if mode == "ambiguous-member" && reads == 2 {
					return objectTestCursor(object, object), nil
				}
				return objectTestCursor(object), nil
			}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
				writes++
				if string(request.modifications[0].values[0]) != "<TTL=90,CN=sample,DC=example>" || len(request.controls) != 1 || request.controls[0].oid != groupPermissiveModify {
					t.Fatal(request)
				}
				return ldapWriteAttempt{State: ldapWriteAccepted}
			})
			ttl := 90 * time.Second
			request := AddGroupMembersRequest{Identity: objectTestIdentity(), Members: []Identity{objectTestIdentity()}, TimeToLive: &ttl}
			if mode == "ambiguous-member" {
				sam, _ := IdentityByAccountName("ambiguous")
				request.Members = []Identity{sam}
			}
			if mode == "assertion" {
				request.Options.ExpectedVersion = &ObjectVersion{Source: client.config.Endpoint, GUID: objectTestGUID(), USNChanged: 7}
			}
			result, err := client.AddGroupMembers(context.Background(), request)
			if mode == "ttl" {
				if err != nil || writes != 1 || result.Mutation.State != ObjectWriteAccepted {
					t.Fatal(result, err)
				}
				return
			}
			if err == nil || writes != 0 || result.Mutation.State != ObjectWriteNotAttempted {
				t.Fatal(result, err)
			}
			if mode == "ambiguous-member" && (result.Members[0].Resolution == nil || len(result.Members[0].Resolution.Candidates) != 2) {
				t.Fatal(result)
			}
		})
	}
}

func TestGroupMembershipRejectsInvalidInputsBeforeConnection(t *testing.T) {
	var client *Client
	for _, ttl := range []time.Duration{-time.Second, time.Second + 1} {
		_, err := client.AddGroupMembers(context.Background(), AddGroupMembersRequest{Identity: objectTestIdentity(), Members: []Identity{objectTestIdentity()}, TimeToLive: &ttl})
		if !errors.Is(err, ErrInvalidGroupMembership) {
			t.Fatal(err)
		}
	}
	for _, members := range [][]Identity{nil, {{}}, make([]Identity, maxGroupWriteMembers+1)} {
		_, err := client.AddGroupMembers(context.Background(), AddGroupMembersRequest{Identity: objectTestIdentity(), Members: members})
		if err == nil || errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
	}
}

type groupMemberTestSession struct {
	testSession
	memberRead func(context.Context, string, []string, bool) (map[string][][]byte, error)
}

func (s groupMemberTestSession) groupMemberBaseObject(ctx context.Context, base string, properties []string, ttl bool) (map[string][][]byte, error) {
	return s.memberRead(ctx, base, properties, ttl)
}

func memberRangeAttributes(name string, values ...string) map[string][][]byte {
	attrs := map[string][][]byte{"objectguid": {objectTestGUID().Bytes()}, "usnchanged": {[]byte("7")}}
	if name != "" {
		attrs[name] = [][]byte{}
		for _, value := range values {
			attrs[name] = append(attrs[name], []byte(value))
		}
	}
	return attrs
}

func memberReadClient(t *testing.T, read func(context.Context, string, []string, bool) (map[string][][]byte, error)) *Client {
	t.Helper()
	client := newClient(Config{Endpoint: Endpoint{Host: "dc.example", Port: 389}, Timeout: time.Second}, groupMemberTestSession{testSession: testSession{
		read: func(context.Context, []string) (map[string][][]byte, error) {
			root := identityTestRoot(CapabilityActiveDirectory)
			root["supportedcontrol"] = [][]byte{[]byte(groupLinkTTL)}
			return root, nil
		},
		search: func(context.Context, SearchOptions) (searchCursor, error) {
			return objectTestCursor(groupTestEntry(2)), nil
		}, finish: func() error { return nil },
	}, memberRead: read})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestGroupMemberLinksRangesBeyondServerThreshold(t *testing.T) {
	reads := 0
	client := memberReadClient(t, func(_ context.Context, base string, attrs []string, ttl bool) (map[string][][]byte, error) {
		if base != objectGUIDTarget(objectTestGUID()) || ttl {
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
		result := memberRangeAttributes(name, values...)
		result["member"] = nil
		return result, nil
	})
	result, err := client.GroupMemberLinks(context.Background(), objectTestIdentity(), GroupMemberLinksOptions{})
	if err != nil || !result.Complete || !result.AttributeReturned || len(result.Members) != 3003 || len(result.Ranges) != 3 || reads != 3 {
		t.Fatal(len(result.Members), result.Complete, err)
	}
}

func TestGroupMemberLinksPartialFailuresAndBounds(t *testing.T) {
	for _, mode := range []string{"gap", "overlap", "missing-tail", "count", "permission", "changed", "wrong-guid", "range-limit", "value-limit", "byte-limit", "malformed-dn", "conflicting-plain"} {
		t.Run(mode, func(t *testing.T) {
			reads := 0
			client := memberReadClient(t, func(_ context.Context, _ string, _ []string, _ bool) (map[string][][]byte, error) {
				reads++
				if reads == 1 {
					return memberRangeAttributes("member;range=0-0", "CN=first,DC=example"), nil
				}
				attrs := memberRangeAttributes("member;range=1-*", "CN=second,DC=example")
				switch mode {
				case "gap":
					attrs = memberRangeAttributes("member;range=2-*", "CN=second,DC=example")
				case "overlap":
					attrs = memberRangeAttributes("member;range=0-*", "CN=second,DC=example")
				case "missing-tail":
					attrs = memberRangeAttributes("")
				case "count":
					attrs = memberRangeAttributes("member;range=1-3", "CN=second,DC=example")
				case "permission":
					return attrs, &LDAPError{Code: 50}
				case "changed":
					attrs["usnchanged"] = [][]byte{[]byte("8")}
				case "wrong-guid":
					attrs["objectguid"] = [][]byte{make([]byte, 16)}
				case "malformed-dn":
					attrs = memberRangeAttributes("member;range=1-*", "not a dn")
				case "conflicting-plain":
					attrs["member"] = [][]byte{[]byte("CN=third,DC=example")}
				}
				return attrs, nil
			})
			options := GroupMemberLinksOptions{}
			switch mode {
			case "range-limit":
				options.MaxRanges = 1
			case "value-limit":
				options.MaxValues = 1
			case "byte-limit":
				options.MaxBytes = 1
			}
			result, err := client.GroupMemberLinks(context.Background(), objectTestIdentity(), options)
			if err == nil || result.Complete || len(result.Ranges) == 0 || (mode != "byte-limit" && len(result.Members) == 0) || reads > 2 {
				t.Fatal(result, err, reads)
			}
			if strings.HasSuffix(mode, "limit") && (!errors.Is(err, ErrGroupMembershipLimit) || reads != 1) {
				t.Fatal(err, reads)
			}
			if (mode == "changed" || mode == "wrong-guid") && !errors.Is(err, ErrGroupMembershipChanged) {
				t.Fatal(err)
			}
		})
	}
}

func TestGroupMemberLinksTTLAndOmission(t *testing.T) {
	for _, mode := range []string{"ttl", "omitted", "empty"} {
		t.Run(mode, func(t *testing.T) {
			client := memberReadClient(t, func(_ context.Context, _ string, _ []string, ttl bool) (map[string][][]byte, error) {
				if !ttl {
					t.Fatal("missing TTL control")
				}
				if mode == "omitted" {
					return memberRangeAttributes(""), nil
				}
				if mode == "empty" {
					return memberRangeAttributes("member"), nil
				}
				return memberRangeAttributes("member;range=0-*", `<TTL=89,CN=Jörg\, Admin,DC=example>`, "CN=permanent,DC=example"), nil
			})
			result, err := client.GroupMemberLinks(context.Background(), objectTestIdentity(), GroupMemberLinksOptions{IncludeTTL: true})
			if err != nil || !result.Complete || result.AttributeReturned != (mode != "omitted") {
				t.Fatal(result, err)
			}
			if mode == "ttl" && (len(result.Members) != 2 || *result.Members[0].RemainingTTLSeconds != 89 || result.Members[1].RemainingTTLSeconds != nil || result.Members[0].ObservedAt.IsZero()) {
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
		values, next, terminal, _, err := groupMemberRange(map[string][][]byte{name: {[]byte("CN=value,DC=example")}}, start)
		if err == nil && !terminal && (next <= start || next-start != uint64(len(values))) {
			t.Fatal(name, start, next)
		}
	})
}

func TestGroupMemberLinksCancellationAndGlobalCatalog(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reads := 0
	client := memberReadClient(t, func(context.Context, string, []string, bool) (map[string][][]byte, error) {
		reads++
		cancel()
		return memberRangeAttributes("member;range=0-0", "CN=first,DC=example"), nil
	})
	result, err := client.GroupMemberLinks(ctx, objectTestIdentity(), GroupMemberLinksOptions{})
	if !errors.Is(err, context.Canceled) || result.Complete || len(result.Members) != 1 || reads != 1 {
		t.Fatal(result, err, reads)
	}
	client.config.Endpoint.Port = 3268
	result, err = client.GroupMemberLinks(context.Background(), objectTestIdentity(), GroupMemberLinksOptions{})
	if !errors.Is(err, ErrGroupMembershipTarget) || result.Complete || reads != 1 {
		t.Fatal(result, err, reads)
	}
}

func TestGroupMembershipLDSDirectReferencesAndAccountGuard(t *testing.T) {
	for _, account := range []bool{false, true} {
		t.Run(fmt.Sprint(account), func(t *testing.T) {
			writes := 0
			client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
				return objectTestCursor(groupTestEntry(2)), nil
			}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
				writes++
				return ldapWriteAttempt{State: ldapWriteAccepted}
			})
			session := client.session.(objectWriteTestSession)
			session.read = func(context.Context, []string) (map[string][][]byte, error) {
				return identityTestRoot(CapabilityADLDS), nil
			}
			client.session = session
			member := groupMemberDN(t, "CN=member,DC=example")
			if account {
				member, _ = IdentityByAccountName("member")
			}
			result, err := client.AddGroupMembers(context.Background(), AddGroupMembersRequest{Identity: objectTestIdentity(), Members: []Identity{member}, Mode: GroupMembershipStrict})
			if account {
				if !errors.Is(err, ErrUnsupportedDirectory) || writes != 0 || result.Mutation.State != ObjectWriteNotAttempted {
					t.Fatal(result, err, writes)
				}
			} else if err != nil || writes != 1 || result.Mutation.State != ObjectWriteAccepted {
				t.Fatal(result, err, writes)
			}
		})
	}
}

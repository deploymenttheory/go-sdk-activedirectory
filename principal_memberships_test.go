package activedirectory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

type membershipWorld struct {
	partition, kind string
	forest          byte
	objects         []Object
	links           map[string][]string
	searches        []SearchOptions
	searchError     func(SearchOptions) error
	tokens          func(string, []string) (map[string][][]byte, error)
	write           func(ldapWriteRequest) ldapWriteAttempt
	gc              bool
	omitMember      bool
}
type membershipTestSession struct {
	groupMemberTestSession
	write func(ldapWriteRequest) ldapWriteAttempt
}

func (s membershipTestSession) ldapWrite(_ context.Context, r ldapWriteRequest) ldapWriteAttempt {
	if s.write == nil {
		return ldapWriteAttempt{Err: ErrUnsupported}
	}
	return s.write(r)
}

func membershipObject(name, partition, kind string, id byte, rid int, domain int) Object {
	guid := GUID{}
	guid[0] = id
	sid, _ := ParseSID(fmt.Sprintf("S-1-5-21-%d-2-3-%d", domain, rid))
	attrs := map[string][][]byte{"objectguid": {guid.Bytes()}, "objectsid": {sid.Bytes()}, "objectclass": {[]byte("top"), []byte(kind)}, "usnchanged": {[]byte("7")}, "name": {[]byte(name)}, "samaccountname": {[]byte(name)}}
	if kind == "group" {
		attrs["grouptype"] = [][]byte{[]byte("-2147483646")}
	}
	if kind == "user" {
		attrs["primarygroupid"] = [][]byte{[]byte("513")}
	}
	return Object{DistinguishedName: "CN=" + name + "," + partition, Attributes: attrs}
}
func membershipObjectKey(object Object) string {
	value, _ := object.Values("objectGUID").Single()
	guid, _ := value.GUID()
	return objectGUIDTarget(guid)
}
func membershipFilter(attribute string, value []byte) string {
	literal := FilterBytes(value)
	if attribute != "objectGUID" && attribute != "objectSid" {
		literal = FilterText(string(value))
	}
	filter, _ := FilterEqual(attribute, literal).LDAP()
	return filter
}
func (w *membershipWorld) client(t *testing.T) *Client {
	t.Helper()
	if w.kind == "" {
		w.kind = CapabilityActiveDirectory
	}
	if w.partition == "" {
		w.partition = "DC=example"
	}
	if w.forest == 0 {
		w.forest = 1
	}
	port := uint16(389)
	if w.gc {
		port = 3268
	}
	client := newClient(Config{Endpoint: Endpoint{Host: "dc." + w.partition, Port: port}, Timeout: 5 * time.Second}, membershipTestSession{groupMemberTestSession: groupMemberTestSession{testSession: testSession{
		base: func(_ context.Context, dn string, properties []string) (map[string][][]byte, error) {
			if dn == "" {
				root := identityTestRoot(w.kind)
				root["defaultnamingcontext"] = [][]byte{[]byte(w.partition)}
				root["namingcontexts"] = [][]byte{[]byte(w.partition)}
				root["configurationnamingcontext"] = [][]byte{[]byte("CN=Configuration,DC=forest")}
				root["isglobalcatalogready"] = [][]byte{[]byte("TRUE")}
				return root, nil
			}
			if dn == "CN=Configuration,DC=forest" {
				guid := GUID{}
				guid[0] = w.forest
				return map[string][][]byte{"objectguid": {guid.Bytes()}}, nil
			}
			if w.tokens != nil {
				return w.tokens(dn, properties)
			}
			return nil, ErrInvalidResult
		},
		search: func(_ context.Context, q SearchOptions) (searchCursor, error) {
			w.searches = append(w.searches, q)
			var objects []Object
			for _, o := range w.objects {
				match := q.Scope == ScopeBase && membershipSameDN(q.Base, o.DistinguishedName)
				if q.Scope != ScopeBase {
					for _, attribute := range []string{"objectGUID", "objectSid", "sAMAccountName", "primaryGroupID"} {
						values, _ := o.Attribute(attribute)
						for _, v := range values {
							if strings.Contains(q.Filter, membershipFilter(attribute, v)) {
								match = true
							}
						}
					}
					if strings.Contains(q.Filter, "(member=") && membershipHasClass(o, "group") {
						for _, dn := range w.links[o.DistinguishedName] {
							encoded, _ := FilterEqual("member", FilterText(dn)).LDAP()
							if strings.Contains(q.Filter, encoded) {
								match = true
							}
						}
					}
				}
				if strings.Contains(q.Filter, "(objectClass=group)") && !membershipHasClass(o, "group") {
					match = false
				}
				if strings.Contains(q.Filter, "groupType:") {
					value, e := o.Values("groupType").Single()
					flags, _ := value.Flags32()
					if e != nil {
						match = false
					} else if strings.Contains(q.Filter, ":=8)") {
						match = match && flags.Has(8)
					} else if strings.Contains(q.Filter, ":=7)") {
						match = match && flags&7 != 0
					}
				}
				if match {
					o.RequestedProperties = slices.Clone(q.Properties)
					objects = append(objects, o)
				}
			}
			if w.searchError != nil {
				if err := w.searchError(q); err != nil {
					return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) { return objects, true, err }, finish: func() error { return nil }}, nil
				}
			}
			return objectTestCursor(objects...), nil
		}, finish: func() error { return nil },
	}, memberRead: func(_ context.Context, dn string, properties []string, _ bool) (map[string][][]byte, error) {
		if len(properties) > 0 && strings.HasPrefix(properties[0], "tokenGroups") && w.tokens != nil {
			return w.tokens(dn, properties)
		}
		for _, o := range w.objects {
			if membershipObjectKey(o) == dn {
				attrs := map[string][][]byte{"objectguid": o.Attributes["objectguid"], "usnchanged": o.Attributes["usnchanged"], "member;range=0-*": {}}
				if w.omitMember {
					delete(attrs, "member;range=0-*")
				}
				for _, link := range w.links[o.DistinguishedName] {
					attrs["member;range=0-*"] = append(attrs["member;range=0-*"], []byte(link))
				}
				return attrs, nil
			}
		}
		return nil, ErrDirectoryObjectNotFound
	}}, write: w.write})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestGroupMembersPrimaryForeignCycleAndDeduplication(t *testing.T) {
	root := membershipObject("root", "DC=example", "group", 1, 1000, 1)
	nested := membershipObject("nested", "DC=example", "group", 2, 1001, 1)
	user := membershipObject("Jörg", "DC=example", "user", 3, 1100, 1)
	primary := membershipObject("primary", "DC=example", "user", 4, 1101, 1)
	primary.Attributes["primarygroupid"] = [][]byte{[]byte("1000")}
	foreign := membershipObject("foreign", "DC=other", "user", 5, 1102, 9)
	fsp := membershipObject("fsp", "DC=example", "foreignSecurityPrincipal", 6, 1102, 9)
	for _, recursive := range []bool{false, true} {
		world := membershipWorld{objects: []Object{root, nested, user, primary, fsp}, links: map[string][]string{root.DistinguishedName: {nested.DistinguishedName, user.DistinguishedName, fsp.DistinguishedName}, nested.DistinguishedName: {root.DistinguishedName, user.DistinguishedName}}}
		other := membershipWorld{partition: "DC=other", forest: 2, objects: []Object{foreign}}
		client, remote := world.client(t), other.client(t)
		result, err := client.GroupMembers(context.Background(), groupMemberDN(t, root.DistinguishedName), GroupMembersOptions{Recursive: recursive, Contexts: []MembershipContext{{Client: remote, Partition: "DC=other"}}})
		want := 4
		if recursive {
			want = 3
		}
		if err != nil || !result.Complete || len(result.Members) != want || len(result.Unresolved) != 0 {
			t.Fatalf("members=%d groups=%d error=%v", len(result.Members), len(result.Groups), err)
		}
		if recursive && len(result.Groups) != 2 {
			t.Fatal("cycle did not terminate", len(result.Groups))
		}
		seen := map[string]bool{}
		primaryFound := false
		for _, member := range result.Members {
			if seen[member.SID.String()] {
				t.Fatal("duplicate principal")
			}
			seen[member.SID.String()] = true
			if member.Object.DistinguishedName == primary.DistinguishedName {
				primaryFound = member.Primary
			}
			if recursive && membershipHasClass(member.Object, "group") {
				t.Fatal("recursive result included nested group")
			}
		}
		if !primaryFound {
			t.Fatal("primary group membership omitted")
		}
	}
}
func TestGroupMembersEmptyAndPrimaryOnlyOmittedMember(t *testing.T) {
	for _, primaryOnly := range []bool{false, true} {
		group := membershipObject("domain-users", "DC=example", "group", 1, 513, 1)
		world := membershipWorld{objects: []Object{group}, omitMember: true}
		if primaryOnly {
			world.objects = append(world.objects, membershipObject("primary-only", "DC=example", "user", 2, 1100, 1))
		}
		client := world.client(t)
		result, err := client.GroupMembers(context.Background(), groupMemberDN(t, group.DistinguishedName), GroupMembersOptions{Recursive: true})
		want := 0
		if primaryOnly {
			want = 1
		}
		if err != nil || !result.Complete || len(result.Members) != want || len(result.Groups) != 1 || result.Groups[0].Links.AttributeReturned || !result.Groups[0].PrimaryMembers.Complete {
			t.Fatal(result, err)
		}
		if primaryOnly && !result.Members[0].Primary {
			t.Fatal("primary-only member lost")
		}
	}
}

func TestGroupMembersRetainsResolvedLinksOnLaterFailure(t *testing.T) {
	group := membershipObject("root", "DC=example", "group", 1, 1000, 1)
	user := membershipObject("user", "DC=example", "user", 2, 1100, 1)
	world := membershipWorld{objects: []Object{group, user}, links: map[string][]string{group.DistinguishedName: {user.DistinguishedName}}, searchError: func(q SearchOptions) error {
		if strings.Contains(q.Filter, "(primaryGroupID=") {
			return &LDAPError{Code: 50}
		}
		return nil
	}}
	result, err := world.client(t).GroupMembers(context.Background(), groupMemberDN(t, group.DistinguishedName), GroupMembersOptions{})
	if !hasLDAPCode(err, 50) || result.Complete || len(result.Groups) != 1 || len(result.Groups[0].Resolutions) != 1 || result.Groups[0].Resolutions[0].Observation.Object == nil || result.Groups[0].Resolutions[0].Observation.Object.DistinguishedName != user.DistinguishedName {
		t.Fatal(result, err)
	}
}

func TestGroupMembersDeduplicatedPrimaryEdgeAndDepthLimit(t *testing.T) {
	root := membershipObject("root", "DC=example", "group", 1, 1000, 1)
	nested := membershipObject("nested", "DC=example", "group", 2, 1001, 1)
	deep := membershipObject("deep", "DC=example", "group", 3, 1002, 1)
	user := membershipObject("user", "DC=example", "user", 4, 1100, 1)
	user.Attributes["primarygroupid"] = [][]byte{[]byte("1001")}
	world := membershipWorld{objects: []Object{root, nested, deep, user}, links: map[string][]string{root.DistinguishedName: {nested.DistinguishedName, user.DistinguishedName}, nested.DistinguishedName: {deep.DistinguishedName}}}
	client := world.client(t)
	result, err := client.GroupMembers(context.Background(), groupMemberDN(t, root.DistinguishedName), GroupMembersOptions{Recursive: true})
	if err != nil || !result.Complete || len(result.Members) != 1 || !result.Members[0].Primary {
		t.Fatal(result, err)
	}
	result, err = client.GroupMembers(context.Background(), groupMemberDN(t, root.DistinguishedName), GroupMembersOptions{Recursive: true, Limits: MembershipLimits{MaxDepth: 1}})
	if !errors.Is(err, ErrMembershipLimit) || !result.LimitReached || result.Complete || len(result.Groups) != 2 || len(result.Members) != 1 {
		t.Fatal(result, err)
	}
}

func TestGroupMembersUnresolvedAndBoundsRetainObservations(t *testing.T) {
	group := membershipObject("root", "DC=example", "group", 1, 1000, 1)
	fsp := membershipObject("fsp", "DC=example", "foreignSecurityPrincipal", 2, 1100, 9)
	world := membershipWorld{objects: []Object{group, fsp}, links: map[string][]string{group.DistinguishedName: {fsp.DistinguishedName, "CN=missing,DC=unconfigured"}}}
	client := world.client(t)
	result, err := client.GroupMembers(context.Background(), groupMemberDN(t, group.DistinguishedName), GroupMembersOptions{Recursive: true})
	if !errors.Is(err, ErrMembershipForeign) || !errors.Is(err, ErrMembershipContext) || result.Complete || len(result.Unresolved) != 2 || result.Unresolved[0].ForeignReference == nil || len(result.Groups[0].Links.Ranges) != 1 {
		t.Fatal(result, err)
	}
	result, err = client.GroupMembers(context.Background(), groupMemberDN(t, group.DistinguishedName), GroupMembersOptions{Limits: MembershipLimits{MaxObjects: 1}})
	if err == nil || !result.LimitReached || result.Complete || len(result.Groups) != 1 {
		t.Fatal(result, err)
	}
}

func TestPrincipalGroupMembershipHomeCatalogAndPrimary(t *testing.T) {
	user := membershipObject("user", "DC=example", "user", 1, 1100, 1)
	primary := membershipObject("primary", "DC=example", "group", 2, 513, 1)
	global := membershipObject("global", "DC=example", "group", 3, 1000, 1)
	local := membershipObject("local", "DC=example", "group", 4, 1001, 1)
	local.Attributes["grouptype"] = [][]byte{[]byte("-2147483644")}
	universal := membershipObject("universal", "DC=other", "group", 5, 1002, 9)
	universal.Attributes["grouptype"] = [][]byte{[]byte("-2147483640")}
	home := membershipWorld{objects: []Object{user, primary, global, local}, links: map[string][]string{global.DistinguishedName: {user.DistinguishedName}, local.DistinguishedName: {user.DistinguishedName}}}
	gc := membershipWorld{gc: true, objects: []Object{universal}, links: map[string][]string{universal.DistinguishedName: {user.DistinguishedName}}}
	client, catalog := home.client(t), gc.client(t)
	result, err := client.PrincipalGroupMembership(context.Background(), groupMemberDN(t, user.DistinguishedName), PrincipalGroupMembershipOptions{GlobalCatalog: catalog})
	if err != nil || !result.Complete || len(result.Groups) != 4 || result.PrimaryGroup == nil || len(result.Searches) != 2 || result.Searches[1].Query.Base != "" {
		t.Fatal(result, err)
	}
	_, err = client.PrincipalGroupMembership(context.Background(), groupMemberDN(t, user.DistinguishedName), PrincipalGroupMembershipOptions{})
	if !errors.Is(err, ErrMembershipGC) {
		t.Fatal(err)
	}
	gc.forest = 2
	_, err = client.PrincipalGroupMembership(context.Background(), groupMemberDN(t, user.DistinguishedName), PrincipalGroupMembershipOptions{GlobalCatalog: catalog})
	if !errors.Is(err, ErrMembershipGC) {
		t.Fatal("accepted unrelated forest catalog", err)
	}
}
func TestPrincipalResourceContextResolvesForeignProxy(t *testing.T) {
	user := membershipObject("user", "DC=example", "user", 1, 1100, 1)
	fsp := membershipObject("proxy", "DC=resource", "foreignSecurityPrincipal", 2, 1100, 1)
	group := membershipObject("local", "DC=resource", "group", 3, 1200, 9)
	home := membershipWorld{objects: []Object{user}}
	resource := membershipWorld{partition: "DC=resource", forest: 2, objects: []Object{fsp, group}, links: map[string][]string{group.DistinguishedName: {fsp.DistinguishedName}}}
	client, remote := home.client(t), resource.client(t)
	result, err := client.PrincipalGroupMembership(context.Background(), groupMemberDN(t, user.DistinguishedName), PrincipalGroupMembershipOptions{ResourceContext: &MembershipContext{Client: remote, Partition: "DC=resource"}})
	if err != nil || !result.Complete || len(result.Groups) != 1 || result.ResourcePrincipal == nil || result.PrimaryGroup != nil {
		t.Fatal(result, err)
	}
	query, _ := result.Searches[0].Query.TypedFilter.LDAP()
	encoded, _ := FilterEqual("member", FilterText(fsp.DistinguishedName)).LDAP()
	if !strings.Contains(query, encoded) {
		t.Fatal(query)
	}
}

func TestPrincipalMembershipPartialSearchAndLDSResource(t *testing.T) {
	for _, kind := range []string{CapabilityActiveDirectory, CapabilityADLDS} {
		for _, failure := range []error{nil, &LDAPError{Code: 50}, context.Canceled, ErrInvalidResult} {
			user := membershipObject("user", "DC=example", "user", 1, 1100, 1)
			group := membershipObject("group", "DC=example", "group", 2, 513, 1)
			world := membershipWorld{kind: kind, objects: []Object{user, group}, links: map[string][]string{group.DistinguishedName: {user.DistinguishedName}}, searchError: func(q SearchOptions) error {
				if strings.Contains(q.Filter, "(member=") {
					return failure
				}
				return nil
			}}
			client := world.client(t)
			result, err := client.PrincipalGroupMembership(context.Background(), groupMemberDN(t, user.DistinguishedName), PrincipalGroupMembershipOptions{ResourceContext: &MembershipContext{Client: client, Partition: "DC=example"}})
			if len(result.Groups) != 1 || len(result.Searches) != 1 || len(result.Searches[0].Observation.Objects) != 1 {
				t.Fatal(result, err)
			}
			if failure == nil {
				if err != nil || !result.Complete {
					t.Fatal(result, err)
				}
			} else if !errors.Is(err, failure) || result.Complete || result.Searches[0].Observation.Complete {
				t.Fatal(result, err)
			}
		}
	}
}

func TestAuthorizationTokenRangesResolveSecurityGroups(t *testing.T) {
	account := membershipObject("user", "DC=example", "user", 1, 1100, 1)
	first := membershipObject("first", "DC=example", "group", 2, 513, 1)
	second := membershipObject("second", "DC=example", "group", 3, 1000, 1)
	for _, mode := range []string{"success", "missing", "gap", "permission", "unresolved", "limit", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			world := membershipWorld{objects: []Object{account, first, second}}
			world.tokens = func(dn string, properties []string) (map[string][][]byte, error) {
				calls++
				if dn != membershipObjectKey(account) || !strings.HasPrefix(properties[0], "tokenGroups;range=") {
					t.Fatal(dn, properties)
				}
				attrs := map[string][][]byte{"objectguid": account.Attributes["objectguid"], "usnchanged": account.Attributes["usnchanged"]}
				if mode == "missing" {
					return attrs, nil
				}
				name, values := "tokengroups;range=0-0", first.Attributes["objectsid"]
				if calls == 2 {
					name, values = "tokengroups;range=1-*", append(slices.Clone(second.Attributes["objectsid"]), first.Attributes["objectsid"]...)
				}
				if mode == "gap" && calls == 2 {
					name = "tokengroups;range=2-*"
				}
				if mode == "malformed" {
					values = [][]byte{{1, 2, 3}}
				}
				attrs[name] = values
				if mode == "permission" && calls == 2 {
					return attrs, &LDAPError{Code: 50}
				}
				return attrs, nil
			}
			if mode == "unresolved" {
				world.objects = []Object{account, first}
			}
			client := world.client(t)
			options := AccountAuthorizationGroupsOptions{}
			if mode == "limit" {
				options.Limits.MaxRanges = 1
			}
			result, err := client.AccountAuthorizationGroups(context.Background(), groupMemberDN(t, account.DistinguishedName), options)
			if mode == "success" {
				if err != nil || !result.Complete || !result.TokensComplete || len(result.Groups) != 2 || len(result.SIDs) != 2 || calls != 2 {
					t.Fatal(result, err)
				}
			} else {
				if err == nil || result.Complete || len(result.Ranges) == 0 {
					t.Fatal(result, err)
				}
				if mode == "unresolved" && (!result.TokensComplete || len(result.SIDs) != 2 || len(result.Resolutions) != 2) {
					t.Fatal(result, err)
				}
				if mode == "permission" && (!hasLDAPCode(err, 50) || len(result.SIDs) != 2 || len(result.Ranges) != 2) {
					t.Fatal(result, err)
				}
				if mode == "limit" && (!result.LimitReached || calls != 1) {
					t.Fatal(result, err)
				}
			}
		})
	}
}

func TestPrincipalMembershipMutationOutcomesAndStopOnUncertain(t *testing.T) {
	principal := membershipObject("principal", "DC=example", "user", 1, 1100, 1)
	for _, remove := range []bool{false, true} {
		objects := []Object{principal}
		var targets []PrincipalMembershipTarget
		for i := 0; i < 4; i++ {
			group := membershipObject(fmt.Sprintf("group%d", i), "DC=example", "group", byte(i+2), 1000+i, 1)
			objects = append(objects, group)
			targets = append(targets, PrincipalMembershipTarget{Identity: groupMemberDN(t, group.DistinguishedName)})
		}
		writes := 0
		world := membershipWorld{objects: objects, write: func(request ldapWriteRequest) ldapWriteAttempt {
			writes++
			operation := uint32(0)
			if remove {
				operation = 1
			}
			if len(request.modifications) != 1 || request.modifications[0].operation != operation || !bytes.Equal(request.modifications[0].values[0], []byte(membershipObjectKey(principal))) {
				t.Fatal(request)
			}
			switch writes {
			case 1:
				return ldapWriteAttempt{State: ldapWriteAccepted}
			case 2:
				return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 50}}
			default:
				return ldapWriteAttempt{State: ldapWriteUncertain, Err: errLDAPWriteUncertain}
			}
		}}
		client := world.client(t)
		request := PrincipalGroupMembershipRequest{Principal: groupMemberDN(t, principal.DistinguishedName), Groups: targets, Mode: GroupMembershipStrict}
		var result PrincipalGroupMembershipMutationResult
		var err error
		if remove {
			result, err = client.RemovePrincipalGroupMembership(context.Background(), request)
		} else {
			result, err = client.AddPrincipalGroupMembership(context.Background(), request)
		}
		if !errors.Is(err, ErrObjectWriteUncertain) || !hasLDAPCode(err, 50) || result.Complete || writes != 3 || result.Processed != 3 || len(result.Outcomes) != 4 || result.Outcomes[0].Result.Mutation.State != ObjectWriteAccepted || result.Outcomes[1].Result.Mutation.State != ObjectWriteRejected || result.Outcomes[2].Result.Mutation.State != ObjectWriteUncertain || result.Outcomes[3].Result.Mutation.State != ObjectWriteNotAttempted {
			t.Fatal(result, err)
		}
	}
}

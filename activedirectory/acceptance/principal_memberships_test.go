package acceptance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_memberships "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/memberships"
)

type InternalMembershipWorld struct {
	InternalPartition, InternalKind string
	InternalForest                  byte
	InternalObjects                 []admodel.Object
	InternalLinks                   map[string][]string
	InternalSearches                []admodel.SearchOptions
	InternalSearchError             func(admodel.SearchOptions) error
	InternalTokens                  func(string, []string) (map[string][][]byte, error)
	InternalWrite                   func(admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt
	InternalGc                      bool
	InternalOmitMember              bool
}
type InternalMembershipTestSession struct {
	InternalGroupMemberTestSession
	InternalWrite func(admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt
}

func (s InternalMembershipTestSession) InternalLdapWrite(
	_ context.Context,
	r admodel.InternalLdapWriteRequest,
) admodel.InternalLdapWriteAttempt {
	if s.InternalWrite == nil {
		return admodel.InternalLdapWriteAttempt{Err: admodel.ErrUnsupported}
	}
	return s.InternalWrite(r)
}

func InternalMembershipObject(
	name, partition, kind string,
	id byte,
	rid int,
	domain int,
) admodel.Object {
	guid := admodel.GUID{}
	guid[0] = id
	sid, _ := admodel.ParseSID(fmt.Sprintf("S-1-5-21-%d-2-3-%d", domain, rid))
	attrs := map[string][][]byte{
		"objectguid":     {guid.Bytes()},
		"objectsid":      {sid.Bytes()},
		"objectclass":    {[]byte("top"), []byte(kind)},
		"usnchanged":     {[]byte("7")},
		"name":           {[]byte(name)},
		"samaccountname": {[]byte(name)},
	}
	if kind == "group" {
		attrs["grouptype"] = [][]byte{[]byte("-2147483646")}
	}
	if kind == "user" {
		attrs["primarygroupid"] = [][]byte{[]byte("513")}
	}
	return admodel.Object{DistinguishedName: "CN=" + name + "," + partition, Attributes: attrs}
}

func InternalMembershipObjectKey(object admodel.Object) string {
	value, _ := object.Values("objectGUID").Single()
	guid, _ := value.GUID()
	return admodel.InternalObjectGUIDTarget(guid)
}

func InternalMembershipFilter(attribute string, value []byte) string {
	literal := admodel.FilterBytes(value)
	if attribute != "objectGUID" && attribute != "objectSid" {
		literal = admodel.FilterText(string(value))
	}
	filter, _ := admodel.FilterEqual(attribute, literal).LDAP()
	return filter
}

func (w *InternalMembershipWorld) InternalClient(t *testing.T) *adengine.Client {
	t.Helper()
	if w.InternalKind == "" {
		w.InternalKind = admodel.CapabilityActiveDirectory
	}
	if w.InternalPartition == "" {
		w.InternalPartition = "DC=example"
	}
	if w.InternalForest == 0 {
		w.InternalForest = 1
	}
	port := uint16(389)
	if w.InternalGc {
		port = 3268
	}
	client := adengine.InternalNewClient(
		admodel.Config{
			Endpoint: admodel.Endpoint{Host: "dc." + w.InternalPartition, Port: port},
			Timeout:  5 * time.Second,
		},
		InternalMembershipTestSession{
			InternalGroupMemberTestSession: InternalGroupMemberTestSession{
				InternalTestSession: InternalTestSession{
					InternalBase: func(_ context.Context, dn string, properties []string) (map[string][][]byte, error) {
						if dn == "" {
							root := InternalIdentityTestRoot(w.InternalKind)
							root["defaultnamingcontext"] = [][]byte{[]byte(w.InternalPartition)}
							root["namingcontexts"] = [][]byte{[]byte(w.InternalPartition)}
							root["configurationnamingcontext"] = [][]byte{
								[]byte("CN=Configuration,DC=forest"),
							}
							root["isglobalcatalogready"] = [][]byte{[]byte("TRUE")}
							return root, nil
						}
						if dn == "CN=Configuration,DC=forest" {
							guid := admodel.GUID{}
							guid[0] = w.InternalForest
							return map[string][][]byte{"objectguid": {guid.Bytes()}}, nil
						}
						if w.InternalTokens != nil {
							return w.InternalTokens(dn, properties)
						}
						return nil, admodel.ErrInvalidResult
					},
					InternalSearch: func(_ context.Context, q admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
						w.InternalSearches = append(w.InternalSearches, q)
						var objects []admodel.Object
						for _, o := range w.InternalObjects {
							match := q.Scope == admodel.ScopeBase &&
								admodel.InternalMembershipSameDN(q.Base, o.DistinguishedName)
							if q.Scope != admodel.ScopeBase {
								for _, attribute := range []string{"objectGUID", "objectSid", "sAMAccountName", "primaryGroupID"} {
									values, _ := o.Attribute(attribute)
									for _, v := range values {
										if strings.Contains(
											q.Filter,
											InternalMembershipFilter(attribute, v),
										) {
											match = true
										}
									}
								}
								if strings.Contains(q.Filter, "(member=") &&
									admodel.InternalMembershipHasClass(o, "group") {
									for _, dn := range w.InternalLinks[o.DistinguishedName] {
										encoded, _ := admodel.FilterEqual("member", admodel.FilterText(dn)).
											LDAP()
										if strings.Contains(q.Filter, encoded) {
											match = true
										}
									}
								}
							}
							if strings.Contains(q.Filter, "(objectClass=group)") &&
								!admodel.InternalMembershipHasClass(o, "group") {
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
						if w.InternalSearchError != nil {
							if err := w.InternalSearchError(q); err != nil {
								return InternalTestSearchCursor{
									InternalRead:   func(context.Context, uint32) ([]admodel.Object, bool, error) { return objects, true, err },
									InternalFinish: func() error { return nil },
								}, nil
							}
						}
						return InternalObjectTestCursor(objects...), nil
					},
					InternalFinish: func() error { return nil },
				},
				InternalMemberRead: func(_ context.Context, dn string, properties []string, _ bool) (map[string][][]byte, error) {
					if len(properties) > 0 && strings.HasPrefix(properties[0], "tokenGroups") &&
						w.InternalTokens != nil {
						return w.InternalTokens(dn, properties)
					}
					for _, o := range w.InternalObjects {
						if InternalMembershipObjectKey(o) == dn {
							attrs := map[string][][]byte{
								"objectguid":       o.Attributes["objectguid"],
								"usnchanged":       o.Attributes["usnchanged"],
								"member;range=0-*": {},
							}
							if w.InternalOmitMember {
								delete(attrs, "member;range=0-*")
							}
							for _, link := range w.InternalLinks[o.DistinguishedName] {
								attrs["member;range=0-*"] = append(
									attrs["member;range=0-*"],
									[]byte(link),
								)
							}
							return attrs, nil
						}
					}
					return nil, admodel.ErrDirectoryObjectNotFound
				},
			},
			InternalWrite: w.InternalWrite,
		},
	)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestGroupMembersPrimaryForeignCycleAndDeduplication(t *testing.T) {
	root := InternalMembershipObject("root", "DC=example", "group", 1, 1000, 1)
	nested := InternalMembershipObject("nested", "DC=example", "group", 2, 1001, 1)
	user := InternalMembershipObject("Jörg", "DC=example", "user", 3, 1100, 1)
	primary := InternalMembershipObject("primary", "DC=example", "user", 4, 1101, 1)
	primary.Attributes["primarygroupid"] = [][]byte{[]byte("1000")}
	foreign := InternalMembershipObject("foreign", "DC=other", "user", 5, 1102, 9)
	fsp := InternalMembershipObject("fsp", "DC=example", "foreignSecurityPrincipal", 6, 1102, 9)
	for _, recursive := range []bool{false, true} {
		world := InternalMembershipWorld{
			InternalObjects: []admodel.Object{root, nested, user, primary, fsp},
			InternalLinks: map[string][]string{
				root.DistinguishedName: {
					nested.DistinguishedName,
					user.DistinguishedName,
					fsp.DistinguishedName,
				},
				nested.DistinguishedName: {root.DistinguishedName, user.DistinguishedName},
			},
		}
		other := InternalMembershipWorld{
			InternalPartition: "DC=other",
			InternalForest:    2,
			InternalObjects:   []admodel.Object{foreign},
		}
		client, remote := world.InternalClient(t), other.InternalClient(t)
		result, err := adservice_memberships.New(client).
			GroupMembers(context.Background(), InternalGroupMemberDN(t, root.DistinguishedName), adengine.GroupMembersOptions{Recursive: recursive, Contexts: []adengine.MembershipContext{{Client: remote, Partition: "DC=other"}}})
		want := 4
		if recursive {
			want = 3
		}
		if err != nil || !result.Complete || len(result.Members) != want ||
			len(result.Unresolved) != 0 {
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
			if recursive && admodel.InternalMembershipHasClass(member.Object, "group") {
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
		group := InternalMembershipObject("domain-users", "DC=example", "group", 1, 513, 1)
		world := InternalMembershipWorld{
			InternalObjects:    []admodel.Object{group},
			InternalOmitMember: true,
		}
		if primaryOnly {
			world.InternalObjects = append(
				world.InternalObjects,
				InternalMembershipObject("primary-only", "DC=example", "user", 2, 1100, 1),
			)
		}
		client := world.InternalClient(t)
		result, err := adservice_memberships.New(client).
			GroupMembers(context.Background(), InternalGroupMemberDN(t, group.DistinguishedName), adengine.GroupMembersOptions{Recursive: true})
		want := 0
		if primaryOnly {
			want = 1
		}
		if err != nil || !result.Complete || len(result.Members) != want ||
			len(result.Groups) != 1 ||
			result.Groups[0].Links.AttributeReturned ||
			!result.Groups[0].PrimaryMembers.Complete {
			t.Fatal(result, err)
		}
		if primaryOnly && !result.Members[0].Primary {
			t.Fatal("primary-only member lost")
		}
	}
}

func TestGroupMembersRetainsResolvedLinksOnLaterFailure(t *testing.T) {
	group := InternalMembershipObject("root", "DC=example", "group", 1, 1000, 1)
	user := InternalMembershipObject("user", "DC=example", "user", 2, 1100, 1)
	world := InternalMembershipWorld{
		InternalObjects: []admodel.Object{group, user},
		InternalLinks:   map[string][]string{group.DistinguishedName: {user.DistinguishedName}},
		InternalSearchError: func(q admodel.SearchOptions) error {
			if strings.Contains(q.Filter, "(primaryGroupID=") {
				return &admodel.LDAPError{Code: 50}
			}
			return nil
		},
	}
	result, err := adservice_memberships.New(world.InternalClient(t)).
		GroupMembers(context.Background(), InternalGroupMemberDN(t, group.DistinguishedName), adengine.GroupMembersOptions{})
	if !InternalHasLDAPCode(err, 50) || result.Complete || len(result.Groups) != 1 ||
		len(result.Groups[0].Resolutions) != 1 ||
		result.Groups[0].Resolutions[0].Observation.Object == nil ||
		result.Groups[0].Resolutions[0].Observation.Object.DistinguishedName != user.DistinguishedName {
		t.Fatal(result, err)
	}
}

func TestGroupMembersDeduplicatedPrimaryEdgeAndDepthLimit(t *testing.T) {
	root := InternalMembershipObject("root", "DC=example", "group", 1, 1000, 1)
	nested := InternalMembershipObject("nested", "DC=example", "group", 2, 1001, 1)
	deep := InternalMembershipObject("deep", "DC=example", "group", 3, 1002, 1)
	user := InternalMembershipObject("user", "DC=example", "user", 4, 1100, 1)
	user.Attributes["primarygroupid"] = [][]byte{[]byte("1001")}
	world := InternalMembershipWorld{
		InternalObjects: []admodel.Object{root, nested, deep, user},
		InternalLinks: map[string][]string{
			root.DistinguishedName:   {nested.DistinguishedName, user.DistinguishedName},
			nested.DistinguishedName: {deep.DistinguishedName},
		},
	}
	client := world.InternalClient(t)
	result, err := adservice_memberships.New(client).
		GroupMembers(context.Background(), InternalGroupMemberDN(t, root.DistinguishedName), adengine.GroupMembersOptions{Recursive: true})
	if err != nil || !result.Complete || len(result.Members) != 1 || !result.Members[0].Primary {
		t.Fatal(result, err)
	}
	result, err = adservice_memberships.New(client).
		GroupMembers(context.Background(), InternalGroupMemberDN(t, root.DistinguishedName), adengine.GroupMembersOptions{Recursive: true, Limits: admodel.MembershipLimits{MaxDepth: 1}})
	if !errors.Is(err, admodel.ErrMembershipLimit) || !result.LimitReached || result.Complete ||
		len(result.Groups) != 2 ||
		len(result.Members) != 1 {
		t.Fatal(result, err)
	}
}

func TestGroupMembersUnresolvedAndBoundsRetainObservations(t *testing.T) {
	group := InternalMembershipObject("root", "DC=example", "group", 1, 1000, 1)
	fsp := InternalMembershipObject("fsp", "DC=example", "foreignSecurityPrincipal", 2, 1100, 9)
	world := InternalMembershipWorld{
		InternalObjects: []admodel.Object{group, fsp},
		InternalLinks: map[string][]string{
			group.DistinguishedName: {fsp.DistinguishedName, "CN=missing,DC=unconfigured"},
		},
	}
	client := world.InternalClient(t)
	result, err := adservice_memberships.New(client).
		GroupMembers(context.Background(), InternalGroupMemberDN(t, group.DistinguishedName), adengine.GroupMembersOptions{Recursive: true})
	if !errors.Is(err, admodel.ErrMembershipForeign) ||
		!errors.Is(err, admodel.ErrMembershipContext) ||
		result.Complete ||
		len(result.Unresolved) != 2 ||
		result.Unresolved[0].ForeignReference == nil ||
		len(result.Groups[0].Links.Ranges) != 1 {
		t.Fatal(result, err)
	}
	result, err = adservice_memberships.New(client).
		GroupMembers(context.Background(), InternalGroupMemberDN(t, group.DistinguishedName), adengine.GroupMembersOptions{Limits: admodel.MembershipLimits{MaxObjects: 1}})
	if err == nil || !result.LimitReached || result.Complete || len(result.Groups) != 1 {
		t.Fatal(result, err)
	}
}

func TestPrincipalGroupMembershipHomeCatalogAndPrimary(t *testing.T) {
	user := InternalMembershipObject("user", "DC=example", "user", 1, 1100, 1)
	primary := InternalMembershipObject("primary", "DC=example", "group", 2, 513, 1)
	global := InternalMembershipObject("global", "DC=example", "group", 3, 1000, 1)
	local := InternalMembershipObject("local", "DC=example", "group", 4, 1001, 1)
	local.Attributes["grouptype"] = [][]byte{[]byte("-2147483644")}
	universal := InternalMembershipObject("universal", "DC=other", "group", 5, 1002, 9)
	universal.Attributes["grouptype"] = [][]byte{[]byte("-2147483640")}
	home := InternalMembershipWorld{
		InternalObjects: []admodel.Object{user, primary, global, local},
		InternalLinks: map[string][]string{
			global.DistinguishedName: {user.DistinguishedName},
			local.DistinguishedName:  {user.DistinguishedName},
		},
	}
	gc := InternalMembershipWorld{
		InternalGc:      true,
		InternalObjects: []admodel.Object{universal},
		InternalLinks:   map[string][]string{universal.DistinguishedName: {user.DistinguishedName}},
	}
	client, catalog := home.InternalClient(t), gc.InternalClient(t)
	result, err := adservice_memberships.New(client).
		PrincipalGroupMembership(context.Background(), InternalGroupMemberDN(t, user.DistinguishedName), adengine.PrincipalGroupMembershipOptions{GlobalCatalog: catalog})
	if err != nil || !result.Complete || len(result.Groups) != 4 || result.PrimaryGroup == nil ||
		len(result.Searches) != 2 ||
		result.Searches[1].Query.Base != "" {
		t.Fatal(result, err)
	}
	_, err = adservice_memberships.New(client).
		PrincipalGroupMembership(context.Background(), InternalGroupMemberDN(t, user.DistinguishedName), adengine.PrincipalGroupMembershipOptions{})
	if !errors.Is(err, admodel.ErrMembershipGC) {
		t.Fatal(err)
	}
	gc.InternalForest = 2
	_, err = adservice_memberships.New(client).
		PrincipalGroupMembership(context.Background(), InternalGroupMemberDN(t, user.DistinguishedName), adengine.PrincipalGroupMembershipOptions{GlobalCatalog: catalog})
	if !errors.Is(err, admodel.ErrMembershipGC) {
		t.Fatal("accepted unrelated forest catalog", err)
	}
}

func TestPrincipalResourceContextResolvesForeignProxy(t *testing.T) {
	user := InternalMembershipObject("user", "DC=example", "user", 1, 1100, 1)
	fsp := InternalMembershipObject("proxy", "DC=resource", "foreignSecurityPrincipal", 2, 1100, 1)
	group := InternalMembershipObject("local", "DC=resource", "group", 3, 1200, 9)
	home := InternalMembershipWorld{InternalObjects: []admodel.Object{user}}
	resource := InternalMembershipWorld{
		InternalPartition: "DC=resource",
		InternalForest:    2,
		InternalObjects:   []admodel.Object{fsp, group},
		InternalLinks:     map[string][]string{group.DistinguishedName: {fsp.DistinguishedName}},
	}
	client, remote := home.InternalClient(t), resource.InternalClient(t)
	result, err := adservice_memberships.New(client).
		PrincipalGroupMembership(context.Background(), InternalGroupMemberDN(t, user.DistinguishedName), adengine.PrincipalGroupMembershipOptions{ResourceContext: &adengine.MembershipContext{Client: remote, Partition: "DC=resource"}})
	if err != nil || !result.Complete || len(result.Groups) != 1 ||
		result.ResourcePrincipal == nil ||
		result.PrimaryGroup != nil {
		t.Fatal(result, err)
	}
	query, _ := result.Searches[0].Query.TypedFilter.LDAP()
	encoded, _ := admodel.FilterEqual("member", admodel.FilterText(fsp.DistinguishedName)).LDAP()
	if !strings.Contains(query, encoded) {
		t.Fatal(query)
	}
}

func TestPrincipalMembershipPartialSearchAndLDSResource(t *testing.T) {
	for _, kind := range []string{admodel.CapabilityActiveDirectory, admodel.CapabilityADLDS} {
		for _, failure := range []error{nil, &admodel.LDAPError{Code: 50}, context.Canceled, admodel.ErrInvalidResult} {
			user := InternalMembershipObject("user", "DC=example", "user", 1, 1100, 1)
			group := InternalMembershipObject("group", "DC=example", "group", 2, 513, 1)
			world := InternalMembershipWorld{
				InternalKind:    kind,
				InternalObjects: []admodel.Object{user, group},
				InternalLinks: map[string][]string{
					group.DistinguishedName: {user.DistinguishedName},
				},
				InternalSearchError: func(q admodel.SearchOptions) error {
					if strings.Contains(q.Filter, "(member=") {
						return failure
					}
					return nil
				},
			}
			client := world.InternalClient(t)
			result, err := adservice_memberships.New(client).
				PrincipalGroupMembership(context.Background(), InternalGroupMemberDN(t, user.DistinguishedName), adengine.PrincipalGroupMembershipOptions{ResourceContext: &adengine.MembershipContext{Client: client, Partition: "DC=example"}})
			if len(result.Groups) != 1 || len(result.Searches) != 1 ||
				len(result.Searches[0].Observation.Objects) != 1 {
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
	account := InternalMembershipObject("user", "DC=example", "user", 1, 1100, 1)
	first := InternalMembershipObject("first", "DC=example", "group", 2, 513, 1)
	second := InternalMembershipObject("second", "DC=example", "group", 3, 1000, 1)
	for _, mode := range []string{"success", "missing", "gap", "permission", "unresolved", "limit", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			world := InternalMembershipWorld{
				InternalObjects: []admodel.Object{account, first, second},
			}
			world.InternalTokens = func(dn string, properties []string) (map[string][][]byte, error) {
				calls++
				if dn != InternalMembershipObjectKey(account) ||
					!strings.HasPrefix(properties[0], "tokenGroups;range=") {
					t.Fatal(dn, properties)
				}
				attrs := map[string][][]byte{
					"objectguid": account.Attributes["objectguid"],
					"usnchanged": account.Attributes["usnchanged"],
				}
				if mode == "missing" {
					return attrs, nil
				}
				name, values := "tokengroups;range=0-0", first.Attributes["objectsid"]
				if calls == 2 {
					name, values = "tokengroups;range=1-*", append(
						slices.Clone(second.Attributes["objectsid"]),
						first.Attributes["objectsid"]...)
				}
				if mode == "gap" && calls == 2 {
					name = "tokengroups;range=2-*"
				}
				if mode == "malformed" {
					values = [][]byte{{1, 2, 3}}
				}
				attrs[name] = values
				if mode == "permission" && calls == 2 {
					return attrs, &admodel.LDAPError{Code: 50}
				}
				return attrs, nil
			}
			if mode == "unresolved" {
				world.InternalObjects = []admodel.Object{account, first}
			}
			client := world.InternalClient(t)
			options := adengine.AccountAuthorizationGroupsOptions{}
			if mode == "limit" {
				options.Limits.MaxRanges = 1
			}
			result, err := adservice_memberships.New(client).
				AccountAuthorizationGroups(context.Background(), InternalGroupMemberDN(t, account.DistinguishedName), options)
			if mode == "success" {
				if err != nil || !result.Complete || !result.TokensComplete ||
					len(result.Groups) != 2 ||
					len(result.SIDs) != 2 ||
					calls != 2 {
					t.Fatal(result, err)
				}
			} else {
				if err == nil || result.Complete || len(result.Ranges) == 0 {
					t.Fatal(result, err)
				}
				if mode == "unresolved" &&
					(!result.TokensComplete || len(result.SIDs) != 2 || len(result.Resolutions) != 2) {
					t.Fatal(result, err)
				}
				if mode == "permission" &&
					(!InternalHasLDAPCode(err, 50) || len(result.SIDs) != 2 || len(result.Ranges) != 2) {
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
	principal := InternalMembershipObject("principal", "DC=example", "user", 1, 1100, 1)
	for _, remove := range []bool{false, true} {
		objects := []admodel.Object{principal}
		var targets []admodel.PrincipalMembershipTarget
		for i := 0; i < 4; i++ {
			group := InternalMembershipObject(
				fmt.Sprintf("group%d", i),
				"DC=example",
				"group",
				byte(i+2),
				1000+i,
				1,
			)
			objects = append(objects, group)
			targets = append(
				targets,
				admodel.PrincipalMembershipTarget{
					Identity: InternalGroupMemberDN(t, group.DistinguishedName),
				},
			)
		}
		writes := 0
		world := InternalMembershipWorld{
			InternalObjects: objects,
			InternalWrite: func(request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				writes++
				operation := uint32(0)
				if remove {
					operation = 1
				}
				if len(request.InternalModifications) != 1 ||
					request.InternalModifications[0].InternalOperation != operation ||
					!bytes.Equal(
						request.InternalModifications[0].InternalValues[0],
						[]byte(InternalMembershipObjectKey(principal)),
					) {
					t.Fatal(request)
				}
				switch writes {
				case 1:
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteAccepted,
					}
				case 2:
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteRejected,
						Err:   &admodel.LDAPError{Code: 50},
					}
				default:
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteUncertain,
						Err:   admodel.InternalLDAPWriteUncertainError(),
					}
				}
			},
		}
		client := world.InternalClient(t)
		request := admodel.PrincipalGroupMembershipRequest{
			Principal: InternalGroupMemberDN(t, principal.DistinguishedName),
			Groups:    targets,
			Mode:      admodel.GroupMembershipStrict,
		}
		var result admodel.PrincipalGroupMembershipMutationResult
		var err error
		if remove {
			result, err = adservice_memberships.New(client).
				RemovePrincipalGroupMembership(context.Background(), request)
		} else {
			result, err = adservice_memberships.New(client).
				AddPrincipalGroupMembership(context.Background(), request)
		}
		if !errors.Is(err, admodel.ErrObjectWriteUncertain) || !InternalHasLDAPCode(err, 50) ||
			result.Complete ||
			writes != 3 ||
			result.Processed != 3 ||
			len(result.Outcomes) != 4 ||
			result.Outcomes[0].Result.Mutation.State != admodel.ObjectWriteAccepted ||
			result.Outcomes[1].Result.Mutation.State != admodel.ObjectWriteRejected ||
			result.Outcomes[2].Result.Mutation.State != admodel.ObjectWriteUncertain ||
			result.Outcomes[3].Result.Mutation.State != admodel.ObjectWriteNotAttempted {
			t.Fatal(result, err)
		}
	}
}

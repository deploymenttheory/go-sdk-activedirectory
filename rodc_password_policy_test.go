package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

type rodcPolicyTestSession struct {
	membershipTestSession
	policy func(context.Context, string, string) (map[string][][]byte, error)
}

func (s *rodcPolicyTestSession) objectSyncPasswordPolicy(ctx context.Context, rodc, account string) (map[string][][]byte, error) {
	return s.policy(ctx, rodc, account)
}

type rodcPolicyFixture struct {
	client                     *Client
	session                    *rodcPolicyTestSession
	world                      *membershipWorld
	controller, account, group Object
	root, dsa                  map[string][][]byte
	values                     map[string][][]byte
	writes, policyCalls        int
	policyValue                string
	policyErr                  error
	attempt                    ldapWriteAttempt
}

func newRODCPolicyFixture(t *testing.T) *rodcPolicyFixture {
	t.Helper()
	f := &rodcPolicyFixture{controller: membershipObject("rodc", "DC=example", "computer", 1, 1000, 1), account: membershipObject(`Dŵr\, Account`, "DC=example", "user", 2, 1100, 1), group: membershipObject("nested-denied", "DC=example", "group", 3, 1200, 1), values: map[string][][]byte{}, policyValue: "1", attempt: ldapWriteAttempt{State: ldapWriteAccepted}}
	f.controller.Attributes["objectclass"] = [][]byte{[]byte("top"), []byte("user"), []byte("computer")}
	f.controller.Attributes["msds-isrodc"] = [][]byte{[]byte("TRUE")}
	f.controller.Attributes["useraccountcontrol"] = [][]byte{[]byte("67112960")}
	f.world = &membershipWorld{objects: []Object{f.controller, f.account, f.group}}
	f.client = f.world.client(t)
	original := f.client.session.(membershipTestSession)
	f.session = &rodcPolicyTestSession{membershipTestSession: original}
	f.root = identityTestRoot(CapabilityActiveDirectory)
	const dsaDN = "CN=NTDS Settings,CN=writable,CN=Servers,CN=Configuration,DC=example"
	f.root["dsservicename"] = [][]byte{[]byte(dsaDN)}
	f.root["configurationnamingcontext"] = [][]byte{[]byte("CN=Configuration,DC=example")}
	f.root["issynchronized"] = [][]byte{[]byte("TRUE")}
	f.root["supportedcontrol"] = [][]byte{[]byte(objectSyncDNInputOID), []byte(groupPermissiveModify)}
	f.dsa = map[string][][]byte{"distinguishedname": {[]byte(dsaDN)}, "objectguid": {objectTestGUID().Bytes()}, "objectclass": {[]byte("nTDSDSA")}, "msds-isrodc": {[]byte("FALSE")}, "msds-hasmasterncs": {[]byte("DC=example")}, "msds-hasfullreplicancs": {[]byte("DC=example")}}
	f.session.base = func(_ context.Context, dn string, _ []string) (map[string][][]byte, error) {
		if dn == "" {
			return f.root, nil
		}
		if dn == dsaDN {
			return f.dsa, nil
		}
		return nil, ErrDirectoryObjectNotFound
	}
	f.session.memberRead = func(_ context.Context, dn string, properties []string, _ bool) (map[string][][]byte, error) {
		if dn != membershipObjectKey(f.controller) {
			t.Fatal(dn)
		}
		attribute, _, _ := strings.Cut(properties[0], ";")
		attrs := map[string][][]byte{"objectguid": f.controller.Attributes["objectguid"], "usnchanged": f.controller.Attributes["usnchanged"]}
		if values, exists := f.values[attribute]; exists {
			attrs[attribute+";range=0-*"] = values
		}
		return attrs, nil
	}
	f.session.policy = func(_ context.Context, rodc, account string) (map[string][][]byte, error) {
		f.policyCalls++
		if rodc != membershipObjectKey(f.controller) || account != membershipObjectKey(f.account) {
			t.Fatal(rodc, account)
		}
		attrs := map[string][][]byte{}
		if f.policyValue != "" {
			attrs["msds-isusercachableatrodc"] = [][]byte{[]byte(f.policyValue)}
		}
		return attrs, f.policyErr
	}
	f.session.write = func(request ldapWriteRequest) ldapWriteAttempt { f.writes++; return f.attempt }
	f.client.session = f.session
	return f
}
func (f *rodcPolicyFixture) controllerIdentity(t *testing.T) Identity {
	return groupMemberDN(t, f.controller.DistinguishedName)
}

func TestRODCResultantPolicyUsesAuthoritativeServerResult(t *testing.T) {
	for _, code := range []string{"0", "1", "2", "-1", "55", "", "broken"} {
		t.Run(code, func(t *testing.T) {
			f := newRODCPolicyFixture(t)
			f.policyValue = code
			// These local observations deliberately conflict with the returned result.
			// The SDK must neither infer allow from a direct list nor expand nested groups.
			f.values["msDS-RevealOnDemandGroup"] = [][]byte{[]byte(f.account.DistinguishedName)}
			f.values["msDS-NeverRevealGroup"] = [][]byte{[]byte(f.group.DistinguishedName)}
			f.world.links = map[string][]string{f.group.DistinguishedName: {f.account.DistinguishedName}}
			result, err := f.client.AccountResultantPasswordReplicationPolicy(context.Background(), f.controllerIdentity(t), groupMemberDN(t, f.account.DistinguishedName), RODCPasswordReplicationOptions{})
			if f.policyCalls != 1 || f.writes != 0 || len(f.world.searches) != 2 {
				t.Fatal(f.policyCalls, f.writes, f.world.searches)
			}
			if code == "" || code == "broken" {
				if err == nil || result.Complete || result.Policy != nil {
					t.Fatal(result, err)
				}
				return
			}
			if err != nil || !result.Complete || result.Policy == nil || fmt.Sprint(*result.Policy) != code {
				t.Fatal(result, err)
			}
			if result.Policy.Known() != (code == "0" || code == "1" || code == "2") {
				t.Fatal(result.Policy)
			}
		})
	}
	f := newRODCPolicyFixture(t)
	f.policyErr = &LDAPError{Code: 50, Diagnostic: "preserved diagnostic"}
	result, err := f.client.AccountResultantPasswordReplicationPolicy(context.Background(), f.controllerIdentity(t), groupMemberDN(t, f.account.DistinguishedName), RODCPasswordReplicationOptions{})
	if !errors.Is(err, ErrRODCPasswordPolicyPermission) || !hasLDAPCode(err, 50) || result.Complete || result.Policy == nil || result.Raw.Values("msDS-IsUserCachableAtRodc").State != AttributePresent {
		t.Fatal(result, err)
	}
}

func TestRODCPasswordListsAndDistinctUsage(t *testing.T) {
	f := newRODCPolicyFixture(t)
	f.values["msDS-RevealOnDemandGroup"] = [][]byte{[]byte(f.account.DistinguishedName)}
	f.values["msDS-NeverRevealGroup"] = [][]byte{[]byte(f.group.DistinguishedName)}
	f.values["msDS-AuthenticatedToAccountlist"] = [][]byte{[]byte(f.account.DistinguishedName)}
	f.values["msDS-RevealedList"] = [][]byte{[]byte("S:10:unicodePwd:" + f.controller.DistinguishedName), []byte("S:23:supplementalCredentials:" + f.controller.DistinguishedName)}
	for _, list := range []RODCPasswordReplicationList{RODCPasswordAllowed, RODCPasswordDenied} {
		result, err := f.client.RODCPasswordReplicationPolicy(context.Background(), f.controllerIdentity(t), list, RODCPasswordReplicationOptions{})
		attribute, _ := list.attribute()
		if err != nil || !result.Complete || len(result.Principals) != 1 || result.Attribute != attribute || !result.AttributeReturned {
			t.Fatal(result, err)
		}
	}
	for _, kind := range []RODCPasswordReplicationUsageKind{RODCPasswordAuthenticated, RODCPasswordRevealed} {
		result, err := f.client.RODCPasswordReplicationPolicyUsage(context.Background(), f.controllerIdentity(t), kind, RODCPasswordReplicationOptions{})
		if err != nil || !result.Complete || len(result.Principals) != 1 {
			t.Fatal(result, err)
		}
		if kind == RODCPasswordRevealed {
			if len(result.Entries) != 2 || result.Entries[0].SecretAttribute != "unicodePwd" || result.Principals[0].Object.DistinguishedName != f.controller.DistinguishedName {
				t.Fatal(result)
			}
		} else if len(result.Entries) != 1 || result.Entries[0].SecretAttribute != "" || result.Principals[0].Object.DistinguishedName != f.account.DistinguishedName {
			t.Fatal(result)
		}
	}
	delete(f.values, "msDS-NeverRevealGroup")
	empty, err := f.client.RODCPasswordReplicationPolicy(context.Background(), f.controllerIdentity(t), RODCPasswordDenied, RODCPasswordReplicationOptions{})
	if err != nil || !empty.Complete || empty.AttributeReturned || len(empty.Entries) != 0 {
		t.Fatal(empty, err)
	}
}

func TestRODCPasswordRangePartialAndUnresolved(t *testing.T) {
	for _, mode := range []string{"success", "gap", "permission", "version", "limit", "unresolved", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			f := newRODCPolicyFixture(t)
			calls := 0
			f.session.memberRead = func(_ context.Context, _ string, properties []string, _ bool) (map[string][][]byte, error) {
				calls++
				name := "msDS-RevealedList;range=0-0"
				value := "S:10:unicodePwd:" + f.account.DistinguishedName
				if calls == 2 {
					name = "msDS-RevealedList;range=1-*"
					value = "S:10:unicodePwd:" + f.controller.DistinguishedName
				}
				if mode == "gap" && calls == 2 {
					name = "msDS-RevealedList;range=2-*"
				}
				if mode == "unresolved" && calls == 1 {
					value = "S:10:unicodePwd:CN=missing,DC=example"
				}
				if mode == "malformed" {
					value = "S:9:unicodePwd:CN=x,DC=example"
				}
				attrs := map[string][][]byte{name: {[]byte(value)}, "objectguid": f.controller.Attributes["objectguid"], "usnchanged": f.controller.Attributes["usnchanged"]}
				if mode == "version" && calls == 2 {
					attrs["usnchanged"] = [][]byte{[]byte("8")}
				}
				if mode == "permission" && calls == 2 {
					return attrs, &LDAPError{Code: 50}
				}
				return attrs, nil
			}
			options := RODCPasswordReplicationOptions{}
			if mode == "limit" {
				options.Limits.MaxRanges = 1
			}
			result, err := f.client.RODCPasswordReplicationPolicyUsage(context.Background(), f.controllerIdentity(t), RODCPasswordRevealed, options)
			if mode == "success" {
				if err != nil || !result.Complete || len(result.Principals) != 2 {
					t.Fatal(result, err)
				}
				return
			}
			if err == nil || result.Complete || len(result.Ranges) == 0 || len(result.Entries) == 0 {
				t.Fatal(result, err)
			}
			if mode == "permission" && (!hasLDAPCode(err, 50) || len(result.Entries) != 2) {
				t.Fatal(result, err)
			}
			if mode == "unresolved" && (len(result.Principals) != 1 || result.Entries[0].Error == nil) {
				t.Fatal(result, err)
			}
			if mode == "limit" && (!result.LimitReached || calls != 1) {
				t.Fatal(result, err)
			}
		})
	}
}

func TestRODCPasswordTargetAndCapabilityGuards(t *testing.T) {
	for _, mode := range []string{"writable-target", "missing-flag", "lds", "gc", "readonly-writer", "wrong-partition", "missing-control"} {
		t.Run(mode, func(t *testing.T) {
			f := newRODCPolicyFixture(t)
			switch mode {
			case "writable-target":
				f.controller.Attributes["msds-isrodc"] = [][]byte{[]byte("FALSE")}
			case "missing-flag":
				f.controller.Attributes["useraccountcontrol"] = [][]byte{[]byte("4096")}
			case "lds":
				f.root["supportedcapabilities"] = [][]byte{[]byte(CapabilityADLDS)}
			case "gc":
				f.client.config.Endpoint.Port = 3268
			case "readonly-writer":
				f.dsa["msds-isrodc"] = [][]byte{[]byte("TRUE")}
			case "wrong-partition":
				f.dsa["msds-hasmasterncs"] = [][]byte{[]byte("DC=other")}
			case "missing-control":
				delete(f.root, "supportedcontrol")
			}
			_, err := f.client.AddRODCPasswordReplicationPolicy(context.Background(), RODCPasswordReplicationChange{Controller: f.controllerIdentity(t), Principals: []Identity{groupMemberDN(t, f.account.DistinguishedName)}})
			if err == nil || f.writes != 0 {
				t.Fatal(err, f.writes)
			}
			if mode == "readonly-writer" {
				return
			}
			if mode == "missing-control" {
				_, err = f.client.AccountResultantPasswordReplicationPolicy(context.Background(), f.controllerIdentity(t), groupMemberDN(t, f.account.DistinguishedName), RODCPasswordReplicationOptions{})
				if !errors.Is(err, ErrRODCPasswordPolicyCapability) || f.policyCalls != 0 {
					t.Fatal(err)
				}
				return
			}
			_, err = f.client.RODCPasswordReplicationPolicy(context.Background(), f.controllerIdentity(t), RODCPasswordAllowed, RODCPasswordReplicationOptions{})
			if err == nil {
				t.Fatal("accepted invalid target")
			}
		})
	}
}

func TestRODCPasswordAtomicChangesAndUncertainty(t *testing.T) {
	for _, remove := range []bool{false, true} {
		for _, list := range []RODCPasswordReplicationList{RODCPasswordAllowed, RODCPasswordDenied} {
			for _, state := range []ldapWriteState{ldapWriteAccepted, ldapWriteRejected, ldapWriteUncertain} {
				f := newRODCPolicyFixture(t)
				attribute, _ := list.attribute()
				f.session.write = func(request ldapWriteRequest) ldapWriteAttempt {
					f.writes++
					operation := uint32(0)
					if remove {
						operation = 1
					}
					if request.dn != membershipObjectKey(f.controller) || len(request.modifications) != 1 || request.modifications[0].attribute != attribute || request.modifications[0].operation != operation || len(request.modifications[0].values) != 2 || len(request.controls) != 0 {
						t.Fatal(request)
					}
					if string(request.modifications[0].values[0]) != membershipObjectKey(f.account) || string(request.modifications[0].values[1]) != membershipObjectKey(f.group) {
						t.Fatal(request)
					}
					attempt := ldapWriteAttempt{State: state}
					if state == ldapWriteRejected {
						attempt.Err = &LDAPError{Code: 50}
					}
					if state == ldapWriteUncertain {
						attempt.Err = errLDAPWriteUncertain
					}
					return attempt
				}
				request := RODCPasswordReplicationChange{Controller: f.controllerIdentity(t), List: list, Principals: []Identity{groupMemberDN(t, f.account.DistinguishedName), groupMemberDN(t, f.group.DistinguishedName)}, Mode: GroupMembershipStrict}
				var result RODCPasswordReplicationMutationResult
				var err error
				if remove {
					result, err = f.client.RemoveRODCPasswordReplicationPolicy(context.Background(), request)
				} else {
					result, err = f.client.AddRODCPasswordReplicationPolicy(context.Background(), request)
				}
				if f.writes != 1 || result.Mutation.Verified || len(result.Principals) != 2 {
					t.Fatal(result, err, f.writes)
				}
				if state == ldapWriteAccepted {
					if err != nil || result.Mutation.State != ObjectWriteAccepted || !result.Mutation.ReadbackComplete {
						t.Fatal(result, err)
					}
				} else if err == nil {
					t.Fatal(result)
				}
				if state == ldapWriteUncertain && !errors.Is(err, ErrObjectWriteUncertain) {
					t.Fatal(err)
				}
				if state == ldapWriteRejected && !errors.Is(err, ErrRODCPasswordPolicyPermission) {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestRODCPasswordPermissiveAndAcceptedReadbackFailure(t *testing.T) {
	f := newRODCPolicyFixture(t)
	f.session.write = func(request ldapWriteRequest) ldapWriteAttempt {
		f.writes++
		if len(request.controls) != 1 || request.controls[0].oid != groupPermissiveModify || !request.controls[0].critical {
			t.Fatal(request.controls)
		}
		f.world.objects = slices.Delete(f.world.objects, 0, 1)
		return ldapWriteAttempt{State: ldapWriteAccepted}
	}
	result, err := f.client.AddRODCPasswordReplicationPolicy(context.Background(), RODCPasswordReplicationChange{Controller: f.controllerIdentity(t), Principals: []Identity{groupMemberDN(t, f.account.DistinguishedName)}})
	if err == nil || result.Mutation.State != ObjectWriteAccepted || result.Mutation.ReadbackComplete || result.Mutation.Verified || f.writes != 1 {
		t.Fatal(result, err)
	}
}

func TestRODCPasswordRejectsDistributionAndUnreadableGroupType(t *testing.T) {
	for _, remove := range []bool{false, true} {
		for _, value := range []string{"2", "missing", "invalid"} {
			f := newRODCPolicyFixture(t)
			if value == "missing" {
				delete(f.group.Attributes, "grouptype")
			} else {
				f.group.Attributes["grouptype"] = [][]byte{[]byte(value)}
			}
			request := RODCPasswordReplicationChange{Controller: f.controllerIdentity(t), Principals: []Identity{groupMemberDN(t, f.group.DistinguishedName)}, Mode: GroupMembershipStrict}
			var result RODCPasswordReplicationMutationResult
			var err error
			if remove {
				result, err = f.client.RemoveRODCPasswordReplicationPolicy(context.Background(), request)
			} else {
				result, err = f.client.AddRODCPasswordReplicationPolicy(context.Background(), request)
			}
			if err == nil || f.writes != 0 || result.Mutation.State != ObjectWriteNotAttempted || len(result.Principals) != 1 || result.Principals[0].Resolution == nil {
				t.Fatal(result, err)
			}
			if !slices.Contains(f.world.searches[len(f.world.searches)-1].Properties, "groupType") {
				t.Fatal("group category was not requested")
			}
		}
	}
}

func TestRODCPasswordInvalidOptionsBeforeIO(t *testing.T) {
	f := newRODCPolicyFixture(t)
	reads := 0
	original := f.session.base
	f.session.base = func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
		reads++
		return original(ctx, dn, properties)
	}
	for _, options := range []RODCPasswordReplicationOptions{{Properties: []string{"bad)"}}, {Limits: MembershipLimits{MaxObjects: 1}}} {
		_, err := f.client.AccountResultantPasswordReplicationPolicy(context.Background(), f.controllerIdentity(t), groupMemberDN(t, f.account.DistinguishedName), options)
		if err == nil || reads != 0 || len(f.world.searches) != 0 {
			t.Fatal(err, reads)
		}
	}
	_, err := f.client.RODCPasswordReplicationPolicy(context.Background(), f.controllerIdentity(t), RODCPasswordAllowed, RODCPasswordReplicationOptions{Limits: MembershipLimits{MaxDepth: 1}})
	if err == nil || reads != 0 {
		t.Fatal(err, reads)
	}
}

func FuzzRODCRevealedMarker(f *testing.F) {
	for _, seed := range []string{"S:10:unicodePwd:CN=Dŵr\\, X,DC=example", "S:23:supplementalCredentials:CN=x,DC=example", "S:999999999999:x:CN=x,DC=y", "S:0::", "S:1:é:CN=x,DC=y"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, value []byte) {
		result, err := decodeRODCPasswordLink(value, true)
		if err == nil {
			if result.SecretAttribute == "" || !objectAttributeName(result.SecretAttribute) {
				t.Fatal(result)
			}
			if _, err := IdentityByDN(result.DistinguishedName); err != nil {
				t.Fatal(err)
			}
		}
	})
}

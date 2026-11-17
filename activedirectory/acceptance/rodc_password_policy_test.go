package acceptance

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_memberships "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/memberships"
)

type InternalRodcPolicyTestSession struct {
	InternalMembershipTestSession
	InternalPolicy func(context.Context, string, string) (map[string][][]byte, error)
}

func (s *InternalRodcPolicyTestSession) InternalObjectSyncPasswordPolicy(
	ctx context.Context,
	rodc, account string,
) (map[string][][]byte, error) {
	return s.InternalPolicy(ctx, rodc, account)
}

type InternalRodcPolicyFixture struct {
	InternalClient                                     *adengine.Client
	InternalSession                                    *InternalRodcPolicyTestSession
	InternalWorld                                      *InternalMembershipWorld
	InternalController, InternalAccount, InternalGroup admodel.Object
	InternalRoot, InternalDsa                          map[string][][]byte
	InternalValues                                     map[string][][]byte
	InternalWrites, InternalPolicyCalls                int
	InternalPolicyValue                                string
	InternalPolicyErr                                  error
	InternalAttempt                                    admodel.InternalLdapWriteAttempt
}

func InternalNewRODCPolicyFixture(t *testing.T) *InternalRodcPolicyFixture {
	t.Helper()
	f := &InternalRodcPolicyFixture{
		InternalController: InternalMembershipObject("rodc", "DC=example", "computer", 1, 1000, 1),
		InternalAccount: InternalMembershipObject(
			`Dŵr\, Account`,
			"DC=example",
			"user",
			2,
			1100,
			1,
		),
		InternalGroup: InternalMembershipObject(
			"nested-denied",
			"DC=example",
			"group",
			3,
			1200,
			1,
		),
		InternalValues:      map[string][][]byte{},
		InternalPolicyValue: "1",
		InternalAttempt: admodel.InternalLdapWriteAttempt{
			State: admodel.InternalLdapWriteAccepted,
		},
	}
	f.InternalController.Attributes["objectclass"] = [][]byte{
		[]byte("top"),
		[]byte("user"),
		[]byte("computer"),
	}
	f.InternalController.Attributes["msds-isrodc"] = [][]byte{[]byte("TRUE")}
	f.InternalController.Attributes["useraccountcontrol"] = [][]byte{[]byte("67112960")}
	f.InternalWorld = &InternalMembershipWorld{
		InternalObjects: []admodel.Object{f.InternalController, f.InternalAccount, f.InternalGroup},
	}
	f.InternalClient = f.InternalWorld.InternalClient(t)
	original := adengine.InternalClientSession(f.InternalClient).(InternalMembershipTestSession)
	f.InternalSession = &InternalRodcPolicyTestSession{InternalMembershipTestSession: original}
	f.InternalRoot = InternalIdentityTestRoot(admodel.CapabilityActiveDirectory)
	const dsaDN = "CN=NTDS Settings,CN=writable,CN=Servers,CN=Configuration,DC=example"
	f.InternalRoot["dsservicename"] = [][]byte{[]byte(dsaDN)}
	f.InternalRoot["configurationnamingcontext"] = [][]byte{[]byte("CN=Configuration,DC=example")}
	f.InternalRoot["issynchronized"] = [][]byte{[]byte("TRUE")}
	f.InternalRoot["supportedcontrol"] = [][]byte{
		[]byte(admodel.InternalObjectSyncDNInputOID),
		[]byte(admodel.InternalGroupPermissiveModify),
	}
	f.InternalDsa = map[string][][]byte{
		"distinguishedname":      {[]byte(dsaDN)},
		"objectguid":             {InternalObjectTestGUID().Bytes()},
		"objectclass":            {[]byte("nTDSDSA")},
		"msds-isrodc":            {[]byte("FALSE")},
		"msds-hasmasterncs":      {[]byte("DC=example")},
		"msds-hasfullreplicancs": {[]byte("DC=example")},
	}
	f.InternalSession.InternalBase = func(_ context.Context, dn string, _ []string) (map[string][][]byte, error) {
		if dn == "" {
			return f.InternalRoot, nil
		}
		if dn == dsaDN {
			return f.InternalDsa, nil
		}
		return nil, admodel.ErrDirectoryObjectNotFound
	}
	f.InternalSession.InternalMemberRead = func(_ context.Context, dn string, properties []string, _ bool) (map[string][][]byte, error) {
		if dn != InternalMembershipObjectKey(f.InternalController) {
			t.Fatal(dn)
		}
		attribute, _, _ := strings.Cut(properties[0], ";")
		attrs := map[string][][]byte{
			"objectguid": f.InternalController.Attributes["objectguid"],
			"usnchanged": f.InternalController.Attributes["usnchanged"],
		}
		if values, exists := f.InternalValues[attribute]; exists {
			attrs[attribute+";range=0-*"] = values
		}
		return attrs, nil
	}
	f.InternalSession.InternalPolicy = func(_ context.Context, rodc, account string) (map[string][][]byte, error) {
		f.InternalPolicyCalls++
		if rodc != InternalMembershipObjectKey(f.InternalController) ||
			account != InternalMembershipObjectKey(f.InternalAccount) {
			t.Fatal(rodc, account)
		}
		attrs := map[string][][]byte{}
		if f.InternalPolicyValue != "" {
			attrs["msds-isusercachableatrodc"] = [][]byte{[]byte(f.InternalPolicyValue)}
		}
		return attrs, f.InternalPolicyErr
	}
	f.InternalSession.InternalWrite = func(request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
		f.InternalWrites++
		return f.InternalAttempt
	}
	(*adengine.InternalClientSessionPointer(f.InternalClient)) = f.InternalSession
	return f
}

func (f *InternalRodcPolicyFixture) InternalControllerIdentity(t *testing.T) admodel.Identity {
	return InternalGroupMemberDN(t, f.InternalController.DistinguishedName)
}

func TestRODCResultantPolicyUsesAuthoritativeServerResult(t *testing.T) {
	for _, code := range []string{"0", "1", "2", "-1", "55", "", "broken"} {
		t.Run(code, func(t *testing.T) {
			f := InternalNewRODCPolicyFixture(t)
			f.InternalPolicyValue = code
			// These local observations deliberately conflict with the returned result.
			// The SDK must neither infer allow from a direct list nor expand nested groups.
			f.InternalValues["msDS-RevealOnDemandGroup"] = [][]byte{
				[]byte(f.InternalAccount.DistinguishedName),
			}
			f.InternalValues["msDS-NeverRevealGroup"] = [][]byte{
				[]byte(f.InternalGroup.DistinguishedName),
			}
			f.InternalWorld.InternalLinks = map[string][]string{
				f.InternalGroup.DistinguishedName: {f.InternalAccount.DistinguishedName},
			}
			result, err := adservice_memberships.New(f.InternalClient).
				AccountResultantPasswordReplicationPolicy(context.Background(), f.InternalControllerIdentity(t), InternalGroupMemberDN(t, f.InternalAccount.DistinguishedName), admodel.RODCPasswordReplicationOptions{})
			if f.InternalPolicyCalls != 1 || f.InternalWrites != 0 ||
				len(f.InternalWorld.InternalSearches) != 2 {
				t.Fatal(f.InternalPolicyCalls, f.InternalWrites, f.InternalWorld.InternalSearches)
			}
			if code == "" || code == "broken" {
				if err == nil || result.Complete || result.Policy != nil {
					t.Fatal(result, err)
				}
				return
			}
			if err != nil || !result.Complete || result.Policy == nil ||
				fmt.Sprint(*result.Policy) != code {
				t.Fatal(result, err)
			}
			if result.Policy.Known() != (code == "0" || code == "1" || code == "2") {
				t.Fatal(result.Policy)
			}
		})
	}
	f := InternalNewRODCPolicyFixture(t)
	f.InternalPolicyErr = &admodel.LDAPError{Code: 50, Diagnostic: "preserved diagnostic"}
	result, err := adservice_memberships.New(f.InternalClient).
		AccountResultantPasswordReplicationPolicy(context.Background(), f.InternalControllerIdentity(t), InternalGroupMemberDN(t, f.InternalAccount.DistinguishedName), admodel.RODCPasswordReplicationOptions{})
	if !errors.Is(err, admodel.ErrRODCPasswordPolicyPermission) || !InternalHasLDAPCode(err, 50) ||
		result.Complete ||
		result.Policy == nil ||
		result.Raw.Values("msDS-IsUserCachableAtRodc").State != admodel.AttributePresent {
		t.Fatal(result, err)
	}
}

func TestRODCPasswordListsAndDistinctUsage(t *testing.T) {
	f := InternalNewRODCPolicyFixture(t)
	f.InternalValues["msDS-RevealOnDemandGroup"] = [][]byte{
		[]byte(f.InternalAccount.DistinguishedName),
	}
	f.InternalValues["msDS-NeverRevealGroup"] = [][]byte{[]byte(f.InternalGroup.DistinguishedName)}
	f.InternalValues["msDS-AuthenticatedToAccountlist"] = [][]byte{
		[]byte(f.InternalAccount.DistinguishedName),
	}
	f.InternalValues["msDS-RevealedList"] = [][]byte{
		[]byte("S:10:unicodePwd:" + f.InternalController.DistinguishedName),
		[]byte("S:23:supplementalCredentials:" + f.InternalController.DistinguishedName),
	}
	for _, list := range []admodel.RODCPasswordReplicationList{admodel.RODCPasswordAllowed, admodel.RODCPasswordDenied} {
		result, err := adservice_memberships.New(f.InternalClient).
			RODCPasswordReplicationPolicy(context.Background(), f.InternalControllerIdentity(t), list, admodel.RODCPasswordReplicationOptions{})
		attribute, _ := admodel.InternalRODCPasswordReplicationListAttribute(list)
		if err != nil || !result.Complete || len(result.Principals) != 1 ||
			result.Attribute != attribute ||
			!result.AttributeReturned {
			t.Fatal(result, err)
		}
	}
	for _, kind := range []admodel.RODCPasswordReplicationUsageKind{admodel.RODCPasswordAuthenticated, admodel.RODCPasswordRevealed} {
		result, err := adservice_memberships.New(f.InternalClient).
			RODCPasswordReplicationPolicyUsage(context.Background(), f.InternalControllerIdentity(t), kind, admodel.RODCPasswordReplicationOptions{})
		if err != nil || !result.Complete || len(result.Principals) != 1 {
			t.Fatal(result, err)
		}
		if kind == admodel.RODCPasswordRevealed {
			if len(result.Entries) != 2 || result.Entries[0].SecretAttribute != "unicodePwd" ||
				result.Principals[0].Object.DistinguishedName != f.InternalController.DistinguishedName {
				t.Fatal(result)
			}
		} else if len(result.Entries) != 1 || result.Entries[0].SecretAttribute != "" || result.Principals[0].Object.DistinguishedName != f.InternalAccount.DistinguishedName {
			t.Fatal(result)
		}
	}
	delete(f.InternalValues, "msDS-NeverRevealGroup")
	empty, err := adservice_memberships.New(f.InternalClient).
		RODCPasswordReplicationPolicy(context.Background(), f.InternalControllerIdentity(t), admodel.RODCPasswordDenied, admodel.RODCPasswordReplicationOptions{})
	if err != nil || !empty.Complete || empty.AttributeReturned || len(empty.Entries) != 0 {
		t.Fatal(empty, err)
	}
}

func TestRODCPasswordRangePartialAndUnresolved(t *testing.T) {
	for _, mode := range []string{"success", "gap", "permission", "version", "limit", "unresolved", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			f := InternalNewRODCPolicyFixture(t)
			calls := 0
			f.InternalSession.InternalMemberRead = func(_ context.Context, _ string, properties []string, _ bool) (map[string][][]byte, error) {
				calls++
				name := "msDS-RevealedList;range=0-0"
				value := "S:10:unicodePwd:" + f.InternalAccount.DistinguishedName
				if calls == 2 {
					name = "msDS-RevealedList;range=1-*"
					value = "S:10:unicodePwd:" + f.InternalController.DistinguishedName
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
				attrs := map[string][][]byte{
					name:         {[]byte(value)},
					"objectguid": f.InternalController.Attributes["objectguid"],
					"usnchanged": f.InternalController.Attributes["usnchanged"],
				}
				if mode == "version" && calls == 2 {
					attrs["usnchanged"] = [][]byte{[]byte("8")}
				}
				if mode == "permission" && calls == 2 {
					return attrs, &admodel.LDAPError{Code: 50}
				}
				return attrs, nil
			}
			options := admodel.RODCPasswordReplicationOptions{}
			if mode == "limit" {
				options.Limits.MaxRanges = 1
			}
			result, err := adservice_memberships.New(f.InternalClient).
				RODCPasswordReplicationPolicyUsage(context.Background(), f.InternalControllerIdentity(t), admodel.RODCPasswordRevealed, options)
			if mode == "success" {
				if err != nil || !result.Complete || len(result.Principals) != 2 {
					t.Fatal(result, err)
				}
				return
			}
			if err == nil || result.Complete || len(result.Ranges) == 0 ||
				len(result.Entries) == 0 {
				t.Fatal(result, err)
			}
			if mode == "permission" && (!InternalHasLDAPCode(err, 50) || len(result.Entries) != 2) {
				t.Fatal(result, err)
			}
			if mode == "unresolved" &&
				(len(result.Principals) != 1 || result.Entries[0].Error == nil) {
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
			f := InternalNewRODCPolicyFixture(t)
			switch mode {
			case "writable-target":
				f.InternalController.Attributes["msds-isrodc"] = [][]byte{[]byte("FALSE")}
			case "missing-flag":
				f.InternalController.Attributes["useraccountcontrol"] = [][]byte{[]byte("4096")}
			case "lds":
				f.InternalRoot["supportedcapabilities"] = [][]byte{[]byte(admodel.CapabilityADLDS)}
			case "gc":
				(*adengine.InternalClientConfigPointer(f.InternalClient)).Endpoint.Port = 3268
			case "readonly-writer":
				f.InternalDsa["msds-isrodc"] = [][]byte{[]byte("TRUE")}
			case "wrong-partition":
				f.InternalDsa["msds-hasmasterncs"] = [][]byte{[]byte("DC=other")}
			case "missing-control":
				delete(f.InternalRoot, "supportedcontrol")
			}
			_, err := adservice_memberships.New(f.InternalClient).
				AddRODCPasswordReplicationPolicy(context.Background(), admodel.RODCPasswordReplicationChange{Controller: f.InternalControllerIdentity(t), Principals: []admodel.Identity{InternalGroupMemberDN(t, f.InternalAccount.DistinguishedName)}})
			if err == nil || f.InternalWrites != 0 {
				t.Fatal(err, f.InternalWrites)
			}
			if mode == "readonly-writer" {
				return
			}
			if mode == "missing-control" {
				_, err = adservice_memberships.New(f.InternalClient).
					AccountResultantPasswordReplicationPolicy(context.Background(), f.InternalControllerIdentity(t), InternalGroupMemberDN(t, f.InternalAccount.DistinguishedName), admodel.RODCPasswordReplicationOptions{})
				if !errors.Is(err, admodel.ErrRODCPasswordPolicyCapability) ||
					f.InternalPolicyCalls != 0 {
					t.Fatal(err)
				}
				return
			}
			_, err = adservice_memberships.New(f.InternalClient).
				RODCPasswordReplicationPolicy(context.Background(), f.InternalControllerIdentity(t), admodel.RODCPasswordAllowed, admodel.RODCPasswordReplicationOptions{})
			if err == nil {
				t.Fatal("accepted invalid target")
			}
		})
	}
}

func TestRODCPasswordAtomicChangesAndUncertainty(t *testing.T) {
	for _, remove := range []bool{false, true} {
		for _, list := range []admodel.RODCPasswordReplicationList{admodel.RODCPasswordAllowed, admodel.RODCPasswordDenied} {
			for _, state := range []admodel.InternalLdapWriteState{admodel.InternalLdapWriteAccepted, admodel.InternalLdapWriteRejected, admodel.InternalLdapWriteUncertain} {
				f := InternalNewRODCPolicyFixture(t)
				attribute, _ := admodel.InternalRODCPasswordReplicationListAttribute(list)
				f.InternalSession.InternalWrite = func(request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					f.InternalWrites++
					operation := uint32(0)
					if remove {
						operation = 1
					}
					if request.InternalDn != InternalMembershipObjectKey(f.InternalController) ||
						len(request.InternalModifications) != 1 ||
						request.InternalModifications[0].InternalAttribute != attribute ||
						request.InternalModifications[0].InternalOperation != operation ||
						len(request.InternalModifications[0].InternalValues) != 2 ||
						len(request.InternalControls) != 0 {
						t.Fatal(request)
					}
					if string(
						request.InternalModifications[0].InternalValues[0],
					) != InternalMembershipObjectKey(
						f.InternalAccount,
					) ||
						string(
							request.InternalModifications[0].InternalValues[1],
						) != InternalMembershipObjectKey(
							f.InternalGroup,
						) {
						t.Fatal(request)
					}
					attempt := admodel.InternalLdapWriteAttempt{State: state}
					if state == admodel.InternalLdapWriteRejected {
						attempt.Err = &admodel.LDAPError{Code: 50}
					}
					if state == admodel.InternalLdapWriteUncertain {
						attempt.Err = admodel.InternalLDAPWriteUncertainError()
					}
					return attempt
				}
				request := admodel.RODCPasswordReplicationChange{
					Controller: f.InternalControllerIdentity(t),
					List:       list,
					Principals: []admodel.Identity{
						InternalGroupMemberDN(t, f.InternalAccount.DistinguishedName),
						InternalGroupMemberDN(t, f.InternalGroup.DistinguishedName),
					},
					Mode: admodel.GroupMembershipStrict,
				}
				var result admodel.RODCPasswordReplicationMutationResult
				var err error
				if remove {
					result, err = adservice_memberships.New(f.InternalClient).
						RemoveRODCPasswordReplicationPolicy(context.Background(), request)
				} else {
					result, err = adservice_memberships.New(f.InternalClient).
						AddRODCPasswordReplicationPolicy(context.Background(), request)
				}
				if f.InternalWrites != 1 || result.Mutation.Verified ||
					len(result.Principals) != 2 {
					t.Fatal(result, err, f.InternalWrites)
				}
				if state == admodel.InternalLdapWriteAccepted {
					if err != nil || result.Mutation.State != admodel.ObjectWriteAccepted ||
						!result.Mutation.ReadbackComplete {
						t.Fatal(result, err)
					}
				} else if err == nil {
					t.Fatal(result)
				}
				if state == admodel.InternalLdapWriteUncertain &&
					!errors.Is(err, admodel.ErrObjectWriteUncertain) {
					t.Fatal(err)
				}
				if state == admodel.InternalLdapWriteRejected &&
					!errors.Is(err, admodel.ErrRODCPasswordPolicyPermission) {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestRODCPasswordPermissiveAndAcceptedReadbackFailure(t *testing.T) {
	f := InternalNewRODCPolicyFixture(t)
	f.InternalSession.InternalWrite = func(request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
		f.InternalWrites++
		if len(request.InternalControls) != 1 ||
			request.InternalControls[0].InternalOid != admodel.InternalGroupPermissiveModify ||
			!request.InternalControls[0].InternalCritical {
			t.Fatal(request.InternalControls)
		}
		f.InternalWorld.InternalObjects = slices.Delete(f.InternalWorld.InternalObjects, 0, 1)
		return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
	}
	result, err := adservice_memberships.New(f.InternalClient).
		AddRODCPasswordReplicationPolicy(context.Background(), admodel.RODCPasswordReplicationChange{Controller: f.InternalControllerIdentity(t), Principals: []admodel.Identity{InternalGroupMemberDN(t, f.InternalAccount.DistinguishedName)}})
	if err == nil || result.Mutation.State != admodel.ObjectWriteAccepted ||
		result.Mutation.ReadbackComplete ||
		result.Mutation.Verified ||
		f.InternalWrites != 1 {
		t.Fatal(result, err)
	}
}

func TestRODCPasswordRejectsDistributionAndUnreadableGroupType(t *testing.T) {
	for _, remove := range []bool{false, true} {
		for _, value := range []string{"2", "missing", "invalid"} {
			f := InternalNewRODCPolicyFixture(t)
			if value == "missing" {
				delete(f.InternalGroup.Attributes, "grouptype")
			} else {
				f.InternalGroup.Attributes["grouptype"] = [][]byte{[]byte(value)}
			}
			request := admodel.RODCPasswordReplicationChange{
				Controller: f.InternalControllerIdentity(t),
				Principals: []admodel.Identity{
					InternalGroupMemberDN(t, f.InternalGroup.DistinguishedName),
				},
				Mode: admodel.GroupMembershipStrict,
			}
			var result admodel.RODCPasswordReplicationMutationResult
			var err error
			if remove {
				result, err = adservice_memberships.New(f.InternalClient).
					RemoveRODCPasswordReplicationPolicy(context.Background(), request)
			} else {
				result, err = adservice_memberships.New(f.InternalClient).
					AddRODCPasswordReplicationPolicy(context.Background(), request)
			}
			if err == nil || f.InternalWrites != 0 ||
				result.Mutation.State != admodel.ObjectWriteNotAttempted ||
				len(result.Principals) != 1 ||
				result.Principals[0].Resolution == nil {
				t.Fatal(result, err)
			}
			if !slices.Contains(
				f.InternalWorld.InternalSearches[len(f.InternalWorld.InternalSearches)-1].Properties,
				"groupType",
			) {
				t.Fatal("group category was not requested")
			}
		}
	}
}

func TestRODCPasswordInvalidOptionsBeforeIO(t *testing.T) {
	f := InternalNewRODCPolicyFixture(t)
	reads := 0
	original := f.InternalSession.InternalBase
	f.InternalSession.InternalBase = func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
		reads++
		return original(ctx, dn, properties)
	}
	for _, options := range []admodel.RODCPasswordReplicationOptions{{Properties: []string{"bad)"}}, {Limits: admodel.MembershipLimits{MaxObjects: 1}}} {
		_, err := adservice_memberships.New(f.InternalClient).
			AccountResultantPasswordReplicationPolicy(context.Background(), f.InternalControllerIdentity(t), InternalGroupMemberDN(t, f.InternalAccount.DistinguishedName), options)
		if err == nil || reads != 0 || len(f.InternalWorld.InternalSearches) != 0 {
			t.Fatal(err, reads)
		}
	}
	_, err := adservice_memberships.New(f.InternalClient).
		RODCPasswordReplicationPolicy(context.Background(), f.InternalControllerIdentity(t), admodel.RODCPasswordAllowed, admodel.RODCPasswordReplicationOptions{Limits: admodel.MembershipLimits{MaxDepth: 1}})
	if err == nil || reads != 0 {
		t.Fatal(err, reads)
	}
}

func FuzzRODCRevealedMarker(f *testing.F) {
	for _, seed := range []string{"S:10:unicodePwd:CN=Dŵr\\, X,DC=example", "S:23:supplementalCredentials:CN=x,DC=example", "S:999999999999:x:CN=x,DC=y", "S:0::", "S:1:é:CN=x,DC=y"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, value []byte) {
		result, err := admodel.InternalDecodeRODCPasswordLink(value, true)
		if err == nil {
			if result.SecretAttribute == "" ||
				!admodel.InternalObjectAttributeName(result.SecretAttribute) {
				t.Fatal(result)
			}
			if _, err := admodel.IdentityByDN(result.DistinguishedName); err != nil {
				t.Fatal(err)
			}
		}
	})
}

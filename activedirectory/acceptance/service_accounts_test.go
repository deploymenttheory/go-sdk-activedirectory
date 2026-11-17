package acceptance

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_service_accounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/service_accounts"
)

// This model supplies explicit directory observations; it does not model AD
// authorization. Native tests below exercise the actual WinLDAP write boundary.
type InternalServiceAccountTestSession struct {
	*InternalOuTestSession
	InternalRoot      map[string][][]byte
	InternalKds       []admodel.Object
	InternalRangeRead func(context.Context, string, []string) (map[string][][]byte, error)
}

func (*InternalServiceAccountTestSession) InternalPasswordProtection(
	ctx context.Context,
	transport admodel.Transport,
) (admodel.PasswordProtection, error) {
	return InternalPasswordTestProtection(ctx, transport)
}

func (*InternalServiceAccountTestSession) InternalNewDirectoryDescriptor(string) ([]byte, error) {
	return InternalOuTestDescriptor(), nil
}

func (*InternalServiceAccountTestSession) InternalEncodeDACL(
	_ []byte,
	aces [][]byte,
) ([]byte, error) {
	return InternalOuTestDescriptor(aces...), nil
}

func (s *InternalServiceAccountTestSession) InternalRangedBaseObject(
	ctx context.Context,
	dn string,
	properties []string,
) (map[string][][]byte, error) {
	if s.InternalRangeRead != nil {
		return s.InternalRangeRead(ctx, dn, properties)
	}
	object, ok := s.InternalLookup(dn)
	if !ok {
		return nil, &admodel.LDAPError{Code: 32}
	}
	attrs := map[string][][]byte{
		"objectguid": object.Attributes["objectguid"],
		"usnchanged": object.Attributes["usnchanged"],
	}
	if values, ok := object.Attributes["msds-hostserviceaccount"]; ok {
		attrs["msds-hostserviceaccount"] = values
	}
	return attrs, nil
}

func (s *InternalServiceAccountTestSession) InternalLdapWrite(
	ctx context.Context,
	request admodel.InternalLdapWriteRequest,
) admodel.InternalLdapWriteAttempt {
	before, _ := s.InternalLookup(request.InternalDn)
	previousLinks := slices.Clone(before.Attributes["msds-hostserviceaccount"])
	if request.InternalOperation == admodel.InternalLdapWriteModify &&
		len(request.InternalModifications) == 1 &&
		strings.EqualFold(request.InternalModifications[0].InternalAttribute, "unicodePwd") {
		s.InternalWrites = append(s.InternalWrites, request)
		if s.InternalFailAt == len(s.InternalWrites) {
			return s.InternalFailure
		}
		return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
	}
	attempt := s.InternalOuTestSession.InternalLdapWrite(ctx, request)
	if attempt.State == admodel.InternalLdapWriteAccepted &&
		request.InternalOperation == admodel.InternalLdapWriteModify {
		for _, mod := range request.InternalModifications {
			if !strings.EqualFold(mod.InternalAttribute, "msDS-HostServiceAccount") {
				continue
			}
			object, _ := s.InternalLookup(request.InternalDn)
			values := previousLinks
			if mod.InternalOperation == 0 {
				values = append(values, mod.InternalValues...)
			} else {
				values = slices.DeleteFunc(values, func(v []byte) bool {
					return slices.ContainsFunc(
						mod.InternalValues,
						func(w []byte) bool { return bytes.Equal(v, w) },
					)
				})
			}
			if len(values) == 0 {
				delete(object.Attributes, "msds-hostserviceaccount")
			} else {
				object.Attributes["msds-hostserviceaccount"] = values
			}
			s.InternalObjects[strings.ToLower(object.DistinguishedName)] = object
		}
	}
	if attempt.State == admodel.InternalLdapWriteAccepted &&
		request.InternalOperation == admodel.InternalLdapWriteAdd {
		object := s.InternalObjects[strings.ToLower(request.InternalDn)]
		class := object.Attributes["objectclass"]
		object.Attributes["objectclass"] = append(
			[][]byte{[]byte("top"), []byte("person"), []byte("user"), []byte("computer")},
			class...)
		object.Attributes["name"] = object.Attributes["cn"]
		sid, _ := admodel.ParseSID("S-1-5-21-1-2-3-1100")
		object.Attributes["objectsid"] = [][]byte{sid.Bytes()}
		object.Attributes["pwdlastset"] = [][]byte{[]byte("12345")}
		s.InternalObjects[strings.ToLower(request.InternalDn)] = object
	}
	return attempt
}

func InternalNewServiceAccountTestClient(
	t *testing.T,
) (*adengine.Client, *InternalServiceAccountTestSession) {
	t.Helper()
	client, ou := InternalNewOUTestClient(t)
	s := &InternalServiceAccountTestSession{
		InternalOuTestSession: ou,
		InternalRoot:          InternalIdentityTestRoot(admodel.CapabilityActiveDirectory),
	}
	s.InternalRoot["domaincontrollerfunctionality"] = [][]byte{[]byte("7")}
	s.InternalRoot["schemanamingcontext"] = [][]byte{
		[]byte("CN=Schema,CN=Configuration,DC=example"),
	}
	s.InternalRoot["configurationnamingcontext"] = [][]byte{[]byte("CN=Configuration,DC=example")}
	s.InternalRoot["currenttime"] = [][]byte{[]byte("20261113000000Z")}
	s.InternalRoot["dsservicename"] = [][]byte{
		[]byte("CN=NTDS Settings,CN=DC,CN=Configuration,DC=example"),
	}
	s.InternalRoot["supportedcontrol"] = [][]byte{[]byte("1.2.840.113556.1.4.1413")}
	start, _ := admodel.FileTimeFromTime(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	s.InternalKds = []admodel.Object{
		{
			DistinguishedName: "CN=key,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,DC=example",
			Attributes: map[string][][]byte{
				"mskds-usestarttime": {[]byte(start.LDAPString())},
			},
		},
	}
	domain := s.InternalObjects["dc=example"]
	domain.Attributes["instancetype"] = [][]byte{[]byte("5")}
	domain.Attributes["otherwellknownobjects"] = [][]byte{
		[]byte("B:32:1EB93889E40C45DF9F0C64D23BBB6237:OU=target,DC=example"),
	}
	s.InternalObjects["dc=example"] = domain
	ou.InternalBase = func(_ context.Context, base string, _ []string) (map[string][][]byte, error) {
		if base != "" {
			return map[string][][]byte{"msds-isrodc": {[]byte("FALSE")}}, nil
		}
		return s.InternalRoot, nil
	}
	oldSearch := ou.InternalSearch
	ou.InternalSearch = func(ctx context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
		for _, p := range query.Properties {
			if admodel.InternalServiceAccountSecret(p) ||
				strings.EqualFold(p, "msKds-RootKeyData") {
				t.Fatal("secret projection", p)
			}
		}
		if strings.HasPrefix(query.Base, "CN=Master Root Keys,") {
			return InternalObjectTestCursor(s.InternalKds...), nil
		}
		if strings.HasPrefix(query.Base, "CN=Schema,") {
			return InternalObjectTestCursor(
				admodel.Object{
					Attributes: map[string][][]byte{
						"rdnattid":            {[]byte("cn")},
						"objectclasscategory": {[]byte("1")},
						"isdefunct":           {[]byte("FALSE")},
					},
				},
			), nil
		}
		return oldSearch(ctx, query)
	}
	(*adengine.InternalClientSessionPointer(client)) = s
	return client, s
}

func InternalServiceAccountTestEntry(kind admodel.ServiceAccountKind) admodel.Object {
	object := InternalComputerTestEntry(4096)
	object.Attributes["objectclass"] = append(
		object.Attributes["objectclass"],
		[]byte(admodel.InternalServiceAccountClassName(kind)),
	)
	object.RequestedProperties = admodel.InternalServiceAccountProperties(nil)
	return object
}

func TestServiceAccountCreateKindsStagesAndOutboundMode(t *testing.T) {
	for _, kind := range []admodel.ServiceAccountKind{admodel.ServiceAccountStandalone, admodel.ServiceAccountGroupManaged} {
		for _, outbound := range []bool{false, true} {
			if kind == admodel.ServiceAccountStandalone && outbound {
				continue
			}
			t.Run(fmt.Sprintf("kind%d-outbound%v", kind, outbound), func(t *testing.T) {
				client, s := InternalNewServiceAccountTestClient(t)
				dns := "svc.example.test"
				request := admodel.CreateServiceAccountRequest{
					Kind:                       kind,
					Name:                       "svc",
					OutboundAuthenticationOnly: outbound,
				}
				if kind == admodel.ServiceAccountGroupManaged && !outbound {
					request.Properties.DNSHostName = &dns
				}
				result, err := adservice_service_accounts.New(client).
					CreateServiceAccount(context.Background(), request)
				if err != nil || !result.Complete || !result.Creation.Verified ||
					result.Account == nil ||
					result.Account.Kind != kind ||
					!result.Prerequisites.Complete {
					t.Fatalf("result=%+v err=%v", result, err)
				}
				if kind == admodel.ServiceAccountStandalone {
					if len(s.InternalWrites) != 3 || result.Password == nil ||
						result.Enable == nil {
						t.Fatal("missing stages", len(s.InternalWrites), result)
					}
					for _, m := range s.InternalWrites[0].InternalModifications {
						if m.InternalAttribute == "useraccountcontrol" &&
							string(m.InternalValues[0]) != "4098" {
							t.Fatal("created enabled before password")
						}
					}
				} else {
					if len(s.InternalWrites) != 1 || result.Password != nil ||
						result.Enable != nil ||
						len(result.Prerequisites.EligibleKDSKeys) != 1 {
						t.Fatal(result, len(s.InternalWrites))
					}
					if result.Account.ManagedPasswordIntervalDays == nil ||
						*result.Account.ManagedPasswordIntervalDays != 30 {
						t.Fatal(result.Account)
					}
				}
				if outbound && result.Account.DNSHostName != nil {
					t.Fatal("outbound mode supplied DNS")
				}
				if _, err := adservice_service_accounts.New(client).
					DeleteServiceAccount(context.Background(), admodel.DeleteServiceAccountRequest{Identity: admodel.InternalObjectGUIDIdentity(*result.Account.GUID)}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestServiceAccountPasswordFailureNeverEnablesOrReplays(t *testing.T) {
	for _, state := range []admodel.InternalLdapWriteState{admodel.InternalLdapWriteRejected, admodel.InternalLdapWriteUncertain} {
		client, s := InternalNewServiceAccountTestClient(t)
		s.InternalFailAt = 2
		s.InternalFailure = admodel.InternalLdapWriteAttempt{
			State: state,
			Err:   &admodel.LDAPError{Code: 50},
		}
		result, err := adservice_service_accounts.New(client).
			CreateServiceAccount(context.Background(), admodel.CreateServiceAccountRequest{Kind: admodel.ServiceAccountStandalone, Name: "svc", InitialPassword: []byte("Caller secret 123!")})
		if !errors.Is(err, admodel.ErrServiceAccountCreationIncomplete) ||
			result.Creation.State != admodel.ObjectWriteAccepted ||
			result.Password == nil ||
			result.Enable != nil ||
			result.Complete ||
			len(s.InternalWrites) != 2 {
			t.Fatal(result, err, len(s.InternalWrites))
		}
		if result.Account.AccountControl.Enabled == nil || *result.Account.AccountControl.Enabled {
			t.Fatal("failed password stage enabled account")
		}
	}
}

func TestServiceAccountPrerequisiteFailuresDoNotWrite(t *testing.T) {
	for _, which := range []string{"LDS", "RODC", "oldDC", "missingTime", "futureKey", "hiddenKey", "missingContainer", "invalidPrincipal"} {
		t.Run(which, func(t *testing.T) {
			client, s := InternalNewServiceAccountTestClient(t)
			dns := "svc.example.test"
			request := admodel.CreateServiceAccountRequest{
				Kind:       admodel.ServiceAccountGroupManaged,
				Name:       "svc",
				Properties: admodel.ServiceAccountProperties{DNSHostName: &dns},
			}
			switch which {
			case "LDS":
				s.InternalRoot["supportedcapabilities"] = [][]byte{[]byte(admodel.CapabilityADLDS)}
			case "RODC":
				s.InternalRoot["supportedcapabilities"] = append(
					s.InternalRoot["supportedcapabilities"],
					[]byte("1.2.840.113556.1.4.1920"),
				)
			case "oldDC":
				s.InternalRoot["domaincontrollerfunctionality"] = [][]byte{[]byte("4")}
			case "missingTime":
				delete(s.InternalRoot, "currenttime")
			case "futureKey":
				s.InternalKds[0].Attributes["mskds-usestarttime"] = [][]byte{
					[]byte("9223372036854775807"),
				}
			case "hiddenKey":
				delete(s.InternalKds[0].Attributes, "mskds-usestarttime")
			case "missingContainer":
				delete(s.InternalObjects["dc=example"].Attributes, "otherwellknownobjects")
			case "invalidPrincipal":
				request.PasswordReaders = []admodel.Identity{InternalOuTestIdentity()}
			}
			result, err := adservice_service_accounts.New(client).
				CreateServiceAccount(context.Background(), request)
			if err == nil || len(s.InternalWrites) != 0 ||
				result.Creation.State != admodel.ObjectWriteNotAttempted {
				t.Fatal(result, err, s.InternalWrites)
			}
		})
	}
}

func TestServiceAccountDescriptorPreservesWholeValueAndUnrelatedRights(t *testing.T) {
	sid, _ := admodel.ParseSID("S-1-5-21-1-2-3-1001")
	other, _ := admodel.ParseSID("S-1-5-21-1-2-3-1002")
	grants, err := admodel.InternalServiceAccountReaderACEs(
		InternalOuTestDescriptor(),
		[]admodel.SID{sid},
	)
	if err != nil {
		t.Fatal(err)
	}
	grant := grants[0]
	binary.LittleEndian.PutUint32(grant[4:8], 0x30)
	deny := slices.Clone(grant)
	deny[0] = 1
	inherited := slices.Clone(grant)
	inherited[1] = 0x10
	raw := InternalOuTestDescriptor(deny, grant, inherited)
	binary.LittleEndian.PutUint16(raw[2:4], 0xb414)
	// Add independent owner/group/SACL components and preserve reserved RM byte.
	raw[1] = 9
	for _, at := range []int{4, 8} {
		binary.LittleEndian.PutUint32(raw[at:at+4], uint32(len(raw)))
		raw = append(raw, sid.Bytes()...)
	}
	sacl := InternalOuTestDescriptor(deny)
	offset := binary.LittleEndian.Uint32(sacl[16:20])
	binary.LittleEndian.PutUint32(raw[12:16], uint32(len(raw)))
	raw = append(raw, sacl[offset:]...)
	aces, err := admodel.InternalServiceAccountReaderACEs(raw, []admodel.SID{other, other})
	if err != nil {
		t.Fatal(err)
	}
	output, err := admodel.InternalPreserveDirectoryDescriptor(
		raw,
		InternalOuTestDescriptor(aces...),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw[:4], output[:4]) {
		t.Fatal("control/RM changed")
	}
	for _, at := range []int{4, 8, 12} {
		before := binary.LittleEndian.Uint32(raw[at : at+4])
		after := binary.LittleEndian.Uint32(output[at : at+4])
		size := len(sid.Bytes())
		if at == 12 {
			size = int(binary.LittleEndian.Uint16(raw[before+2 : before+4]))
		}
		if !bytes.Equal(raw[before:before+uint32(size)], output[after:after+uint32(size)]) {
			t.Fatal("component changed", at)
		}
	}
	acl, _ := admodel.InternalDecodeDirectoryDACL(output)
	if len(acl.InternalAces) != 4 || !bytes.Equal(acl.InternalAces[0], deny) ||
		binary.LittleEndian.Uint32(acl.InternalAces[1][4:8]) != 0x20 ||
		!bytes.Equal(acl.InternalAces[3], inherited) {
		t.Fatal(acl)
	}
	readers, err := admodel.InternalServiceAccountDescriptorReaders(output)
	if err != nil || len(readers) != 1 || readers[0].String() != other.String() {
		t.Fatal(readers, err)
	}
}

func TestServiceAccountUpdateControlsConflictsAndUnreadableDescriptor(t *testing.T) {
	for _, which := range []string{"missingDescriptor", "standaloneReaders", "secretProjection", "rawPassword", "rawInterval", "dMSA"} {
		t.Run(which, func(t *testing.T) {
			client, s := InternalNewServiceAccountTestClient(t)
			object := InternalServiceAccountTestEntry(admodel.ServiceAccountGroupManaged)
			s.InternalObjects[strings.ToLower(object.DistinguishedName)] = object
			request := admodel.UpdateServiceAccountRequest{Identity: InternalObjectTestIdentity()}
			description := "change"
			request.Properties.Description = &description
			switch which {
			case "missingDescriptor":
				empty := []admodel.Identity{}
				request.PasswordReaders = &empty
			case "standaloneReaders":
				object.Attributes["objectclass"][len(object.Attributes["objectclass"])-1] = []byte(
					"msDS-ManagedServiceAccount",
				)
				empty := []admodel.Identity{}
				request.PasswordReaders = &empty
			case "secretProjection":
				request.Options.Properties = []string{"msDS-ManagedPassword"}
			case "rawPassword":
				request.Changes = []admodel.AttributeChange{
					{Attribute: "unicodePwd", Kind: admodel.AttributeClear},
				}
			case "rawInterval":
				request.Changes = []admodel.AttributeChange{
					{Attribute: "msDS-ManagedPasswordInterval", Kind: admodel.AttributeClear},
				}
			case "dMSA":
				object.Attributes["objectclass"] = append(
					object.Attributes["objectclass"],
					[]byte("msDS-DelegatedManagedServiceAccount"),
				)
			}
			result, err := adservice_service_accounts.New(client).
				UpdateServiceAccount(context.Background(), request)
			if err == nil || len(s.InternalWrites) != 0 ||
				result.Mutation.State != admodel.ObjectWriteNotAttempted {
				t.Fatal(result, err)
			}
		})
	}
}

func TestServiceAccountAssociationsRangeReadbackAndGUIDDedupe(t *testing.T) {
	client, s := InternalNewServiceAccountTestClient(t)
	computer := InternalComputerTestEntry(4096)
	s.InternalObjects[strings.ToLower(computer.DistinguishedName)] = computer
	account := InternalServiceAccountTestEntry(admodel.ServiceAccountStandalone)
	account.DistinguishedName = "CN=svc,DC=example"
	account.Attributes["objectguid"] = [][]byte{make([]byte, 16)}
	account.Attributes["objectguid"][0][0] = 8
	s.InternalObjects[strings.ToLower(account.DistinguishedName)] = account
	identity, _ := admodel.IdentityByDN(account.DistinguishedName)
	ranges := 0
	s.InternalRangeRead = func(_ context.Context, _ string, properties []string) (map[string][][]byte, error) {
		ranges++
		attrs := map[string][][]byte{
			"objectguid": computer.Attributes["objectguid"],
			"usnchanged": computer.Attributes["usnchanged"],
		}
		if ranges%2 == 1 {
			if !strings.Contains(properties[0], "range=0-") {
				t.Fatal(properties)
			}
			attrs["msds-hostserviceaccount;range=0-0"] = [][]byte{[]byte("CN=unrelated,DC=example")}
		} else {
			if !strings.Contains(properties[0], "range=1-") {
				t.Fatal(properties)
			}
			attrs["msds-hostserviceaccount;range=1-*"] = [][]byte{[]byte("cn=svc,dc=example")}
		}
		return attrs, nil
	}
	result, err := adservice_service_accounts.New(client).
		AddComputerServiceAccounts(context.Background(), admodel.ComputerServiceAccountRequest{Computer: InternalObjectTestIdentity(), Accounts: []admodel.Identity{identity}})
	if err != nil || !result.Mutation.Verified || ranges != 2 || result.Links == nil ||
		len(result.Links.Links) != 2 {
		t.Fatal(result, err, ranges)
	}
	guid, _ := account.Values("objectGUID").Single()
	id, _ := guid.GUID()
	result, err = adservice_service_accounts.New(client).
		AddComputerServiceAccounts(context.Background(), admodel.ComputerServiceAccountRequest{Computer: InternalObjectTestIdentity(), Accounts: []admodel.Identity{identity, admodel.InternalObjectGUIDIdentity(id)}})
	if !errors.Is(err, admodel.ErrInvalidServiceAccount) || len(s.InternalWrites) != 1 {
		t.Fatal(result, err)
	}
}

func TestServiceAccountRangesKeepPartialAndLimits(t *testing.T) {
	for _, which := range []string{"limit", "gap", "changed", "cleanup", "omitted"} {
		t.Run(which, func(t *testing.T) {
			client, s := InternalNewServiceAccountTestClient(t)
			object := InternalComputerTestEntry(4096)
			s.InternalObjects[strings.ToLower(object.DistinguishedName)] = object
			calls := 0
			cleanup := errors.New("cleanup")
			s.InternalRangeRead = func(context.Context, string, []string) (map[string][][]byte, error) {
				calls++
				attrs := map[string][][]byte{
					"objectguid": object.Attributes["objectguid"],
					"usnchanged": object.Attributes["usnchanged"],
				}
				if which == "omitted" {
					return attrs, nil
				}
				key := "msds-hostserviceaccount;range=0-0"
				if calls > 1 {
					key = "msds-hostserviceaccount;range=2-*"
				}
				attrs[key] = [][]byte{[]byte("CN=svc,DC=example")}
				if which == "changed" {
					attrs["usnchanged"] = [][]byte{[]byte("8")}
				}
				if which == "cleanup" {
					return attrs, cleanup
				}
				return attrs, nil
			}
			options := admodel.ComputerServiceAccountsOptions{}
			if which == "limit" {
				options.MaxValues = 1
			}
			result, err := adservice_service_accounts.New(client).
				ComputerServiceAccounts(context.Background(), InternalObjectTestIdentity(), options)
			if which == "omitted" {
				if err != nil || !result.Complete || result.AttributeReturned {
					t.Fatal(result, err)
				}
				return
			}
			if err == nil || result.Complete || len(result.Ranges) == 0 || len(result.Links) == 0 {
				t.Fatal(result, err)
			}
			if which == "limit" && !errors.Is(err, admodel.ErrServiceAccountAssociationLimit) {
				t.Fatal(err)
			}
		})
	}
}

func TestServiceAccountAssociationRemoveAndUncertainOutcomes(t *testing.T) {
	for _, which := range []string{"keepOther", "lastHidden", "rejected", "uncertain"} {
		t.Run(which, func(t *testing.T) {
			client, s := InternalNewServiceAccountTestClient(t)
			computer := InternalComputerTestEntry(4096)
			account := InternalServiceAccountTestEntry(admodel.ServiceAccountStandalone)
			account.DistinguishedName = "CN=svc,DC=example"
			account.Attributes["objectguid"] = [][]byte{make([]byte, 16)}
			s.InternalObjects[strings.ToLower(account.DistinguishedName)] = account
			computer.Attributes["msds-hostserviceaccount"] = [][]byte{
				[]byte(account.DistinguishedName),
			}
			if which == "keepOther" {
				computer.Attributes["msds-hostserviceaccount"] = append(
					computer.Attributes["msds-hostserviceaccount"],
					[]byte("CN=other,DC=example"),
				)
			}
			s.InternalObjects[strings.ToLower(computer.DistinguishedName)] = computer
			if which == "rejected" || which == "uncertain" {
				s.InternalFailAt = 1
				state := admodel.InternalLdapWriteRejected
				if which == "uncertain" {
					state = admodel.InternalLdapWriteUncertain
				}
				s.InternalFailure = admodel.InternalLdapWriteAttempt{
					State: state,
					Err:   &admodel.LDAPError{Code: 50},
				}
			}
			id, _ := admodel.IdentityByDN(account.DistinguishedName)
			result, err := adservice_service_accounts.New(client).
				RemoveComputerServiceAccounts(context.Background(), admodel.ComputerServiceAccountRequest{Computer: InternalObjectTestIdentity(), Accounts: []admodel.Identity{id}})
			if len(s.InternalWrites) != 1 {
				t.Fatal("replay", s.InternalWrites)
			}
			switch which {
			case "keepOther":
				if err != nil || !result.Mutation.Verified {
					t.Fatal(result, err)
				}
			case "lastHidden":
				if !errors.Is(err, admodel.ErrObjectVerification) ||
					result.Mutation.State != admodel.ObjectWriteAccepted ||
					result.Mutation.Verified ||
					result.Links == nil ||
					result.Links.AttributeReturned {
					t.Fatal(result, err)
				}
			case "uncertain":
				if !errors.Is(err, admodel.ErrObjectWriteUncertain) ||
					result.Mutation.State != admodel.ObjectWriteUncertain {
					t.Fatal(result, err)
				}
			default:
				if !errors.Is(err, admodel.ErrObjectWritePermission) ||
					result.Mutation.State != admodel.ObjectWriteRejected {
					t.Fatal(result, err)
				}
			}
		})
	}
}

func TestServiceAccountCommonPropertyPathsAndNoOpVersion(t *testing.T) {
	client, s := InternalNewServiceAccountTestClient(t)
	object := InternalServiceAccountTestEntry(admodel.ServiceAccountGroupManaged)
	object.Attributes["msds-supportedencryptiontypes"] = [][]byte{[]byte("1073741848")}
	s.InternalObjects[strings.ToLower(object.DistinguishedName)] = object
	compound, home, expires := true, "https://service.example", admodel.FileTime(
		9223372036854775807,
	)
	request := admodel.UpdateServiceAccountRequest{
		Identity: InternalObjectTestIdentity(),
		Properties: admodel.ServiceAccountProperties{
			CompoundIdentitySupported: &compound,
			HomePage:                  &home,
			AccountExpires:            &expires,
		},
		Changes: []admodel.AttributeChange{
			{
				Attribute: "userCertificate",
				Kind:      admodel.AttributeSet,
				Values:    []admodel.RawValue{admodel.NewRawValue([]byte{0, 255, 1})},
			},
			{
				Attribute: "msDS-AssignedAuthNPolicy",
				Kind:      admodel.AttributeSet,
				Values: []admodel.RawValue{
					admodel.NewRawValue([]byte("CN=policy,CN=Configuration,DC=example")),
				},
			},
			{
				Attribute: "msDS-AllowedToActOnBehalfOfOtherIdentity",
				Kind:      admodel.AttributeSet,
				Values:    []admodel.RawValue{admodel.NewRawValue(InternalOuTestDescriptor())},
			},
		},
	}
	result, err := adservice_service_accounts.New(client).
		UpdateServiceAccount(context.Background(), request)
	if err != nil || !result.Mutation.Verified || result.Account.CompoundIdentitySupported == nil ||
		!*result.Account.CompoundIdentitySupported ||
		*result.Account.SupportedEncryptionTypes != 0x40000058 ||
		*result.Account.HomePage != home ||
		*result.Account.AccountExpires != expires ||
		!bytes.Equal(result.Account.Certificates.Values[0].Bytes(), []byte{0, 255, 1}) {
		t.Fatal(result, err)
	}
	result, err = adservice_service_accounts.New(client).
		UpdateServiceAccount(context.Background(), admodel.UpdateServiceAccountRequest{Identity: InternalObjectTestIdentity(), Properties: admodel.ServiceAccountProperties{CompoundIdentitySupported: &compound}, Options: admodel.ObjectMutationOptions{ExpectedVersion: &admodel.ObjectVersion{Source: (*adengine.InternalClientConfigPointer(client)).Endpoint, GUID: InternalObjectTestGUID(), USNChanged: 7}}})
	if !errors.Is(err, admodel.ErrObjectControlUnsupported) ||
		result.Mutation.State != admodel.ObjectWriteNotAttempted ||
		len(s.InternalWrites) != 1 {
		t.Fatal(result, err)
	}
}

func FuzzServiceAccountDescriptorBounds(f *testing.F) {
	f.Add(InternalOuTestDescriptor())
	f.Add([]byte{1, 0, 4, 128})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			return
		}
		_, err := admodel.InternalServiceAccountReaderACEs(raw, nil)
		if err != nil {
			return
		}
		out, err := admodel.InternalPreserveDirectoryDescriptor(raw, InternalOuTestDescriptor())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = admodel.InternalDecodeDirectoryDACL(out); err != nil {
			t.Fatal(err)
		}
	})
}

func TestServiceAccountAssociationHardCapsAndCanceledBatch(t *testing.T) {
	var closed *adengine.Client
	for _, options := range []admodel.ComputerServiceAccountsOptions{{MaxValues: admodel.InternalServiceAccountMaxLinks + 1}, {MaxRanges: admodel.InternalServiceAccountMaxRanges + 1}, {MaxBytes: admodel.InternalServiceAccountMaxBytes + 1}} {
		if _, err := adservice_service_accounts.New(closed).
			ComputerServiceAccounts(context.Background(), InternalObjectTestIdentity(), options); !errors.Is(
			err,
			admodel.ErrInvalidServiceAccount,
		) {
			t.Fatal(options, err)
		}
	}
	client, s := InternalNewServiceAccountTestClient(t)
	object := InternalComputerTestEntry(4096)
	s.InternalObjects[strings.ToLower(object.DistinguishedName)] = object
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.InternalRangeRead = func(context.Context, string, []string) (map[string][][]byte, error) {
		cancel()
		return map[string][][]byte{
			"objectguid":                        object.Attributes["objectguid"],
			"usnchanged":                        object.Attributes["usnchanged"],
			"msds-hostserviceaccount;range=0-*": {[]byte("CN=svc,DC=example")},
		}, nil
	}
	result, err := adservice_service_accounts.New(client).
		ComputerServiceAccounts(ctx, InternalObjectTestIdentity(), admodel.ComputerServiceAccountsOptions{})
	if !errors.Is(err, context.Canceled) || result.Complete || len(result.Ranges) != 1 ||
		len(result.Ranges[0].Attributes) == 0 {
		t.Fatal(result, err)
	}
}

package activedirectory

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
)

// This model supplies explicit directory observations; it does not model AD
// authorization. Native tests below exercise the actual WinLDAP write boundary.
type serviceAccountTestSession struct {
	*ouTestSession
	root      map[string][][]byte
	kds       []Object
	rangeRead func(context.Context, string, []string) (map[string][][]byte, error)
}

func (*serviceAccountTestSession) passwordProtection(ctx context.Context, transport Transport) (PasswordProtection, error) {
	return passwordTestProtection(ctx, transport)
}
func (*serviceAccountTestSession) newDirectoryDescriptor(string) ([]byte, error) {
	return ouTestDescriptor(), nil
}
func (*serviceAccountTestSession) encodeDACL(_ []byte, aces [][]byte) ([]byte, error) {
	return ouTestDescriptor(aces...), nil
}
func (s *serviceAccountTestSession) rangedBaseObject(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
	if s.rangeRead != nil {
		return s.rangeRead(ctx, dn, properties)
	}
	object, ok := s.lookup(dn)
	if !ok {
		return nil, &LDAPError{Code: 32}
	}
	attrs := map[string][][]byte{"objectguid": object.Attributes["objectguid"], "usnchanged": object.Attributes["usnchanged"]}
	if values, ok := object.Attributes["msds-hostserviceaccount"]; ok {
		attrs["msds-hostserviceaccount"] = values
	}
	return attrs, nil
}
func (s *serviceAccountTestSession) ldapWrite(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
	before, _ := s.lookup(request.dn)
	previousLinks := slices.Clone(before.Attributes["msds-hostserviceaccount"])
	if request.operation == ldapWriteModify && len(request.modifications) == 1 && strings.EqualFold(request.modifications[0].attribute, "unicodePwd") {
		s.writes = append(s.writes, request)
		if s.failAt == len(s.writes) {
			return s.failure
		}
		return ldapWriteAttempt{State: ldapWriteAccepted}
	}
	attempt := s.ouTestSession.ldapWrite(ctx, request)
	if attempt.State == ldapWriteAccepted && request.operation == ldapWriteModify {
		for _, mod := range request.modifications {
			if !strings.EqualFold(mod.attribute, "msDS-HostServiceAccount") {
				continue
			}
			object, _ := s.lookup(request.dn)
			values := previousLinks
			if mod.operation == 0 {
				values = append(values, mod.values...)
			} else {
				values = slices.DeleteFunc(values, func(v []byte) bool {
					return slices.ContainsFunc(mod.values, func(w []byte) bool { return bytes.Equal(v, w) })
				})
			}
			if len(values) == 0 {
				delete(object.Attributes, "msds-hostserviceaccount")
			} else {
				object.Attributes["msds-hostserviceaccount"] = values
			}
			s.objects[strings.ToLower(object.DistinguishedName)] = object
		}
	}
	if attempt.State == ldapWriteAccepted && request.operation == ldapWriteAdd {
		object := s.objects[strings.ToLower(request.dn)]
		class := object.Attributes["objectclass"]
		object.Attributes["objectclass"] = append([][]byte{[]byte("top"), []byte("person"), []byte("user"), []byte("computer")}, class...)
		object.Attributes["name"] = object.Attributes["cn"]
		sid, _ := ParseSID("S-1-5-21-1-2-3-1100")
		object.Attributes["objectsid"] = [][]byte{sid.Bytes()}
		object.Attributes["pwdlastset"] = [][]byte{[]byte("12345")}
		s.objects[strings.ToLower(request.dn)] = object
	}
	return attempt
}
func newServiceAccountTestClient(t *testing.T) (*Client, *serviceAccountTestSession) {
	t.Helper()
	client, ou := newOUTestClient(t)
	s := &serviceAccountTestSession{ouTestSession: ou, root: identityTestRoot(CapabilityActiveDirectory)}
	s.root["domaincontrollerfunctionality"] = [][]byte{[]byte("7")}
	s.root["schemanamingcontext"] = [][]byte{[]byte("CN=Schema,CN=Configuration,DC=example")}
	s.root["configurationnamingcontext"] = [][]byte{[]byte("CN=Configuration,DC=example")}
	s.root["currenttime"] = [][]byte{[]byte("20261113000000Z")}
	s.root["dsservicename"] = [][]byte{[]byte("CN=NTDS Settings,CN=DC,CN=Configuration,DC=example")}
	s.root["supportedcontrol"] = [][]byte{[]byte("1.2.840.113556.1.4.1413")}
	start, _ := FileTimeFromTime(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	s.kds = []Object{{DistinguishedName: "CN=key,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,DC=example", Attributes: map[string][][]byte{"mskds-usestarttime": {[]byte(start.LDAPString())}}}}
	domain := s.objects["dc=example"]
	domain.Attributes["instancetype"] = [][]byte{[]byte("5")}
	domain.Attributes["otherwellknownobjects"] = [][]byte{[]byte("B:32:1EB93889E40C45DF9F0C64D23BBB6237:OU=target,DC=example")}
	s.objects["dc=example"] = domain
	ou.base = func(_ context.Context, base string, _ []string) (map[string][][]byte, error) {
		if base != "" {
			return map[string][][]byte{"msds-isrodc": {[]byte("FALSE")}}, nil
		}
		return s.root, nil
	}
	oldSearch := ou.search
	ou.search = func(ctx context.Context, query SearchOptions) (searchCursor, error) {
		for _, p := range query.Properties {
			if serviceAccountSecret(p) || strings.EqualFold(p, "msKds-RootKeyData") {
				t.Fatal("secret projection", p)
			}
		}
		if strings.HasPrefix(query.Base, "CN=Master Root Keys,") {
			return objectTestCursor(s.kds...), nil
		}
		if strings.HasPrefix(query.Base, "CN=Schema,") {
			return objectTestCursor(Object{Attributes: map[string][][]byte{"rdnattid": {[]byte("cn")}, "objectclasscategory": {[]byte("1")}, "isdefunct": {[]byte("FALSE")}}}), nil
		}
		return oldSearch(ctx, query)
	}
	client.session = s
	return client, s
}
func serviceAccountTestEntry(kind ServiceAccountKind) Object {
	object := computerTestEntry(4096)
	object.Attributes["objectclass"] = append(object.Attributes["objectclass"], []byte(serviceAccountClassName(kind)))
	object.RequestedProperties = serviceAccountProperties(nil)
	return object
}
func TestServiceAccountCreateKindsStagesAndOutboundMode(t *testing.T) {
	for _, kind := range []ServiceAccountKind{ServiceAccountStandalone, ServiceAccountGroupManaged} {
		for _, outbound := range []bool{false, true} {
			if kind == ServiceAccountStandalone && outbound {
				continue
			}
			t.Run(fmt.Sprintf("kind%d-outbound%v", kind, outbound), func(t *testing.T) {
				client, s := newServiceAccountTestClient(t)
				dns := "svc.example.test"
				request := CreateServiceAccountRequest{Kind: kind, Name: "svc", OutboundAuthenticationOnly: outbound}
				if kind == ServiceAccountGroupManaged && !outbound {
					request.Properties.DNSHostName = &dns
				}
				result, err := client.CreateServiceAccount(context.Background(), request)
				if err != nil || !result.Complete || !result.Creation.Verified || result.Account == nil || result.Account.Kind != kind || !result.Prerequisites.Complete {
					t.Fatalf("result=%+v err=%v", result, err)
				}
				if kind == ServiceAccountStandalone {
					if len(s.writes) != 3 || result.Password == nil || result.Enable == nil {
						t.Fatal("missing stages", len(s.writes), result)
					}
					for _, m := range s.writes[0].modifications {
						if m.attribute == "useraccountcontrol" && string(m.values[0]) != "4098" {
							t.Fatal("created enabled before password")
						}
					}
				} else {
					if len(s.writes) != 1 || result.Password != nil || result.Enable != nil || len(result.Prerequisites.EligibleKDSKeys) != 1 {
						t.Fatal(result, len(s.writes))
					}
					if result.Account.ManagedPasswordIntervalDays == nil || *result.Account.ManagedPasswordIntervalDays != 30 {
						t.Fatal(result.Account)
					}
				}
				if outbound && result.Account.DNSHostName != nil {
					t.Fatal("outbound mode supplied DNS")
				}
				if _, err := client.DeleteServiceAccount(context.Background(), DeleteServiceAccountRequest{Identity: objectGUIDIdentity(*result.Account.GUID)}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
func TestServiceAccountPasswordFailureNeverEnablesOrReplays(t *testing.T) {
	for _, state := range []ldapWriteState{ldapWriteRejected, ldapWriteUncertain} {
		client, s := newServiceAccountTestClient(t)
		s.failAt = 2
		s.failure = ldapWriteAttempt{State: state, Err: &LDAPError{Code: 50}}
		result, err := client.CreateServiceAccount(context.Background(), CreateServiceAccountRequest{Kind: ServiceAccountStandalone, Name: "svc", InitialPassword: []byte("Caller secret 123!")})
		if !errors.Is(err, ErrServiceAccountCreationIncomplete) || result.Creation.State != ObjectWriteAccepted || result.Password == nil || result.Enable != nil || result.Complete || len(s.writes) != 2 {
			t.Fatal(result, err, len(s.writes))
		}
		if result.Account.AccountControl.Enabled == nil || *result.Account.AccountControl.Enabled {
			t.Fatal("failed password stage enabled account")
		}
	}
}
func TestServiceAccountPrerequisiteFailuresDoNotWrite(t *testing.T) {
	for _, which := range []string{"LDS", "RODC", "oldDC", "missingTime", "futureKey", "hiddenKey", "missingContainer", "invalidPrincipal"} {
		t.Run(which, func(t *testing.T) {
			client, s := newServiceAccountTestClient(t)
			dns := "svc.example.test"
			request := CreateServiceAccountRequest{Kind: ServiceAccountGroupManaged, Name: "svc", Properties: ServiceAccountProperties{DNSHostName: &dns}}
			switch which {
			case "LDS":
				s.root["supportedcapabilities"] = [][]byte{[]byte(CapabilityADLDS)}
			case "RODC":
				s.root["supportedcapabilities"] = append(s.root["supportedcapabilities"], []byte("1.2.840.113556.1.4.1920"))
			case "oldDC":
				s.root["domaincontrollerfunctionality"] = [][]byte{[]byte("4")}
			case "missingTime":
				delete(s.root, "currenttime")
			case "futureKey":
				s.kds[0].Attributes["mskds-usestarttime"] = [][]byte{[]byte("9223372036854775807")}
			case "hiddenKey":
				delete(s.kds[0].Attributes, "mskds-usestarttime")
			case "missingContainer":
				delete(s.objects["dc=example"].Attributes, "otherwellknownobjects")
			case "invalidPrincipal":
				request.PasswordReaders = []Identity{ouTestIdentity()}
			}
			result, err := client.CreateServiceAccount(context.Background(), request)
			if err == nil || len(s.writes) != 0 || result.Creation.State != ObjectWriteNotAttempted {
				t.Fatal(result, err, s.writes)
			}
		})
	}
}
func TestServiceAccountDescriptorPreservesWholeValueAndUnrelatedRights(t *testing.T) {
	sid, _ := ParseSID("S-1-5-21-1-2-3-1001")
	other, _ := ParseSID("S-1-5-21-1-2-3-1002")
	grants, err := serviceAccountReaderACEs(ouTestDescriptor(), []SID{sid})
	if err != nil {
		t.Fatal(err)
	}
	grant := grants[0]
	binary.LittleEndian.PutUint32(grant[4:8], 0x30)
	deny := slices.Clone(grant)
	deny[0] = 1
	inherited := slices.Clone(grant)
	inherited[1] = 0x10
	raw := ouTestDescriptor(deny, grant, inherited)
	binary.LittleEndian.PutUint16(raw[2:4], 0xb414)
	// Add independent owner/group/SACL components and preserve reserved RM byte.
	raw[1] = 9
	for _, at := range []int{4, 8} {
		binary.LittleEndian.PutUint32(raw[at:at+4], uint32(len(raw)))
		raw = append(raw, sid.Bytes()...)
	}
	sacl := ouTestDescriptor(deny)
	offset := binary.LittleEndian.Uint32(sacl[16:20])
	binary.LittleEndian.PutUint32(raw[12:16], uint32(len(raw)))
	raw = append(raw, sacl[offset:]...)
	aces, err := serviceAccountReaderACEs(raw, []SID{other, other})
	if err != nil {
		t.Fatal(err)
	}
	output, err := preserveDirectoryDescriptor(raw, ouTestDescriptor(aces...))
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
	acl, _ := decodeDirectoryDACL(output)
	if len(acl.aces) != 4 || !bytes.Equal(acl.aces[0], deny) || binary.LittleEndian.Uint32(acl.aces[1][4:8]) != 0x20 || !bytes.Equal(acl.aces[3], inherited) {
		t.Fatal(acl)
	}
	readers, err := serviceAccountDescriptorReaders(output)
	if err != nil || len(readers) != 1 || readers[0].String() != other.String() {
		t.Fatal(readers, err)
	}
}
func TestServiceAccountUpdateControlsConflictsAndUnreadableDescriptor(t *testing.T) {
	for _, which := range []string{"missingDescriptor", "standaloneReaders", "secretProjection", "rawPassword", "rawInterval", "dMSA"} {
		t.Run(which, func(t *testing.T) {
			client, s := newServiceAccountTestClient(t)
			object := serviceAccountTestEntry(ServiceAccountGroupManaged)
			s.objects[strings.ToLower(object.DistinguishedName)] = object
			request := UpdateServiceAccountRequest{Identity: objectTestIdentity()}
			description := "change"
			request.Properties.Description = &description
			switch which {
			case "missingDescriptor":
				empty := []Identity{}
				request.PasswordReaders = &empty
			case "standaloneReaders":
				object.Attributes["objectclass"][len(object.Attributes["objectclass"])-1] = []byte("msDS-ManagedServiceAccount")
				empty := []Identity{}
				request.PasswordReaders = &empty
			case "secretProjection":
				request.Options.Properties = []string{"msDS-ManagedPassword"}
			case "rawPassword":
				request.Changes = []AttributeChange{{Attribute: "unicodePwd", Kind: AttributeClear}}
			case "rawInterval":
				request.Changes = []AttributeChange{{Attribute: "msDS-ManagedPasswordInterval", Kind: AttributeClear}}
			case "dMSA":
				object.Attributes["objectclass"] = append(object.Attributes["objectclass"], []byte("msDS-DelegatedManagedServiceAccount"))
			}
			result, err := client.UpdateServiceAccount(context.Background(), request)
			if err == nil || len(s.writes) != 0 || result.Mutation.State != ObjectWriteNotAttempted {
				t.Fatal(result, err)
			}
		})
	}
}
func TestServiceAccountAssociationsRangeReadbackAndGUIDDedupe(t *testing.T) {
	client, s := newServiceAccountTestClient(t)
	computer := computerTestEntry(4096)
	s.objects[strings.ToLower(computer.DistinguishedName)] = computer
	account := serviceAccountTestEntry(ServiceAccountStandalone)
	account.DistinguishedName = "CN=svc,DC=example"
	account.Attributes["objectguid"] = [][]byte{make([]byte, 16)}
	account.Attributes["objectguid"][0][0] = 8
	s.objects[strings.ToLower(account.DistinguishedName)] = account
	identity, _ := IdentityByDN(account.DistinguishedName)
	ranges := 0
	s.rangeRead = func(_ context.Context, _ string, properties []string) (map[string][][]byte, error) {
		ranges++
		attrs := map[string][][]byte{"objectguid": computer.Attributes["objectguid"], "usnchanged": computer.Attributes["usnchanged"]}
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
	result, err := client.AddComputerServiceAccounts(context.Background(), ComputerServiceAccountRequest{Computer: objectTestIdentity(), Accounts: []Identity{identity}})
	if err != nil || !result.Mutation.Verified || ranges != 2 || result.Links == nil || len(result.Links.Links) != 2 {
		t.Fatal(result, err, ranges)
	}
	guid, _ := account.Values("objectGUID").Single()
	id, _ := guid.GUID()
	result, err = client.AddComputerServiceAccounts(context.Background(), ComputerServiceAccountRequest{Computer: objectTestIdentity(), Accounts: []Identity{identity, objectGUIDIdentity(id)}})
	if !errors.Is(err, ErrInvalidServiceAccount) || len(s.writes) != 1 {
		t.Fatal(result, err)
	}
}
func TestServiceAccountRangesKeepPartialAndLimits(t *testing.T) {
	for _, which := range []string{"limit", "gap", "changed", "cleanup", "omitted"} {
		t.Run(which, func(t *testing.T) {
			client, s := newServiceAccountTestClient(t)
			object := computerTestEntry(4096)
			s.objects[strings.ToLower(object.DistinguishedName)] = object
			calls := 0
			cleanup := errors.New("cleanup")
			s.rangeRead = func(context.Context, string, []string) (map[string][][]byte, error) {
				calls++
				attrs := map[string][][]byte{"objectguid": object.Attributes["objectguid"], "usnchanged": object.Attributes["usnchanged"]}
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
			options := ComputerServiceAccountsOptions{}
			if which == "limit" {
				options.MaxValues = 1
			}
			result, err := client.ComputerServiceAccounts(context.Background(), objectTestIdentity(), options)
			if which == "omitted" {
				if err != nil || !result.Complete || result.AttributeReturned {
					t.Fatal(result, err)
				}
				return
			}
			if err == nil || result.Complete || len(result.Ranges) == 0 || len(result.Links) == 0 {
				t.Fatal(result, err)
			}
			if which == "limit" && !errors.Is(err, ErrServiceAccountAssociationLimit) {
				t.Fatal(err)
			}
		})
	}
}

func TestServiceAccountAssociationRemoveAndUncertainOutcomes(t *testing.T) {
	for _, which := range []string{"keepOther", "lastHidden", "rejected", "uncertain"} {
		t.Run(which, func(t *testing.T) {
			client, s := newServiceAccountTestClient(t)
			computer := computerTestEntry(4096)
			account := serviceAccountTestEntry(ServiceAccountStandalone)
			account.DistinguishedName = "CN=svc,DC=example"
			account.Attributes["objectguid"] = [][]byte{make([]byte, 16)}
			s.objects[strings.ToLower(account.DistinguishedName)] = account
			computer.Attributes["msds-hostserviceaccount"] = [][]byte{[]byte(account.DistinguishedName)}
			if which == "keepOther" {
				computer.Attributes["msds-hostserviceaccount"] = append(computer.Attributes["msds-hostserviceaccount"], []byte("CN=other,DC=example"))
			}
			s.objects[strings.ToLower(computer.DistinguishedName)] = computer
			if which == "rejected" || which == "uncertain" {
				s.failAt = 1
				state := ldapWriteRejected
				if which == "uncertain" {
					state = ldapWriteUncertain
				}
				s.failure = ldapWriteAttempt{State: state, Err: &LDAPError{Code: 50}}
			}
			id, _ := IdentityByDN(account.DistinguishedName)
			result, err := client.RemoveComputerServiceAccounts(context.Background(), ComputerServiceAccountRequest{Computer: objectTestIdentity(), Accounts: []Identity{id}})
			if len(s.writes) != 1 {
				t.Fatal("replay", s.writes)
			}
			switch which {
			case "keepOther":
				if err != nil || !result.Mutation.Verified {
					t.Fatal(result, err)
				}
			case "lastHidden":
				if !errors.Is(err, ErrObjectVerification) || result.Mutation.State != ObjectWriteAccepted || result.Mutation.Verified || result.Links == nil || result.Links.AttributeReturned {
					t.Fatal(result, err)
				}
			case "uncertain":
				if !errors.Is(err, ErrObjectWriteUncertain) || result.Mutation.State != ObjectWriteUncertain {
					t.Fatal(result, err)
				}
			default:
				if !errors.Is(err, ErrObjectWritePermission) || result.Mutation.State != ObjectWriteRejected {
					t.Fatal(result, err)
				}
			}
		})
	}
}
func TestServiceAccountCommonPropertyPathsAndNoOpVersion(t *testing.T) {
	client, s := newServiceAccountTestClient(t)
	object := serviceAccountTestEntry(ServiceAccountGroupManaged)
	object.Attributes["msds-supportedencryptiontypes"] = [][]byte{[]byte("1073741848")}
	s.objects[strings.ToLower(object.DistinguishedName)] = object
	compound, home, expires := true, "https://service.example", FileTime(9223372036854775807)
	request := UpdateServiceAccountRequest{Identity: objectTestIdentity(), Properties: ServiceAccountProperties{CompoundIdentitySupported: &compound, HomePage: &home, AccountExpires: &expires}, Changes: []AttributeChange{{Attribute: "userCertificate", Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte{0, 255, 1})}}, {Attribute: "msDS-AssignedAuthNPolicy", Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte("CN=policy,CN=Configuration,DC=example"))}}, {Attribute: "msDS-AllowedToActOnBehalfOfOtherIdentity", Kind: AttributeSet, Values: []RawValue{NewRawValue(ouTestDescriptor())}}}}
	result, err := client.UpdateServiceAccount(context.Background(), request)
	if err != nil || !result.Mutation.Verified || result.Account.CompoundIdentitySupported == nil || !*result.Account.CompoundIdentitySupported || *result.Account.SupportedEncryptionTypes != 0x40000058 || *result.Account.HomePage != home || *result.Account.AccountExpires != expires || !bytes.Equal(result.Account.Certificates.Values[0].Bytes(), []byte{0, 255, 1}) {
		t.Fatal(result, err)
	}
	result, err = client.UpdateServiceAccount(context.Background(), UpdateServiceAccountRequest{Identity: objectTestIdentity(), Properties: ServiceAccountProperties{CompoundIdentitySupported: &compound}, Options: ObjectMutationOptions{ExpectedVersion: &ObjectVersion{Source: client.config.Endpoint, GUID: objectTestGUID(), USNChanged: 7}}})
	if !errors.Is(err, ErrObjectControlUnsupported) || result.Mutation.State != ObjectWriteNotAttempted || len(s.writes) != 1 {
		t.Fatal(result, err)
	}
}
func FuzzServiceAccountDescriptorBounds(f *testing.F) {
	f.Add(ouTestDescriptor())
	f.Add([]byte{1, 0, 4, 128})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			return
		}
		_, err := serviceAccountReaderACEs(raw, nil)
		if err != nil {
			return
		}
		out, err := preserveDirectoryDescriptor(raw, ouTestDescriptor())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = decodeDirectoryDACL(out); err != nil {
			t.Fatal(err)
		}
	})
}

func TestServiceAccountAssociationHardCapsAndCanceledBatch(t *testing.T) {
	var closed *Client
	for _, options := range []ComputerServiceAccountsOptions{{MaxValues: serviceAccountMaxLinks + 1}, {MaxRanges: serviceAccountMaxRanges + 1}, {MaxBytes: serviceAccountMaxBytes + 1}} {
		if _, err := closed.ComputerServiceAccounts(context.Background(), objectTestIdentity(), options); !errors.Is(err, ErrInvalidServiceAccount) {
			t.Fatal(options, err)
		}
	}
	client, s := newServiceAccountTestClient(t)
	object := computerTestEntry(4096)
	s.objects[strings.ToLower(object.DistinguishedName)] = object
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.rangeRead = func(context.Context, string, []string) (map[string][][]byte, error) {
		cancel()
		return map[string][][]byte{"objectguid": object.Attributes["objectguid"], "usnchanged": object.Attributes["usnchanged"], "msds-hostserviceaccount;range=0-*": {[]byte("CN=svc,DC=example")}}, nil
	}
	result, err := client.ComputerServiceAccounts(ctx, objectTestIdentity(), ComputerServiceAccountsOptions{})
	if !errors.Is(err, context.Canceled) || result.Complete || len(result.Ranges) != 1 || len(result.Ranges[0].Attributes) == 0 {
		t.Fatal(result, err)
	}
}

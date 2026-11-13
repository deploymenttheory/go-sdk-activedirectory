package activedirectory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func computerTestEntry(flags Flags32) Object {
	entry := userTestEntry(flags)
	entry.Attributes["objectclass"] = append(entry.Attributes["objectclass"], []byte("computer"))
	entry.Attributes["samaccountname"] = [][]byte{[]byte("HOST$")}
	entry.Attributes["pwdlastset"] = [][]byte{[]byte("1234")}
	return entry
}
func TestComputerSAMAndTypedMapping(t *testing.T) {
	for _, name := range []string{"HOST", "HOST$", "HOST$$", "$", "", "李", "a\x00b"} {
		got, err := computerSAM(name)
		invalid := name == "HOST$$" || name == "$" || name == "" || strings.ContainsRune(name, 0)
		if invalid {
			if !errors.Is(err, ErrInvalidComputer) {
				t.Fatal(name, got, err)
			}
		} else if err != nil || got != strings.TrimSuffix(name, "$")+"$" {
			t.Fatal(name, got, err)
		}
	}
	entry := computerTestEntry(0x40081000)
	entry.Attributes["dnshostname"] = [][]byte{[]byte("host.example.test")}
	entry.Attributes["operatingsystem"] = [][]byte{[]byte("Windows Server 2025")}
	entry.Attributes["location"] = [][]byte{[]byte("東京")}
	entry.Attributes["accountexpires"] = [][]byte{[]byte("9223372036854775807")}
	entry.Attributes["msds-supportedencryptiontypes"] = [][]byte{[]byte("-2147483304")}
	entry.Attributes["serviceprincipalname;range=0-0"] = [][]byte{[]byte("HOST/a")}
	entry.Attributes["usercertificate"] = [][]byte{{0, 255, 1}}
	entry.RequestedProperties = computerProperties(nil)
	computer, err := decodeComputer(entry, DirectoryADDS)
	if err != nil || computer.DNSHostName == nil || *computer.DNSHostName != "host.example.test" || computer.Location == nil || *computer.Location != "東京" || computer.AccountExpires == nil || uint64(*computer.AccountExpires) != 9223372036854775807 || computer.AccountControl.Enabled == nil || !*computer.AccountControl.Enabled || computer.AccountControl.TrustedForDelegation == nil || !*computer.AccountControl.TrustedForDelegation || computer.SupportedEncryptionTypes == nil || *computer.SupportedEncryptionTypes != 0x80000158 || *computer.KerberosEncryptionTypes != 0x18 || !*computer.CompoundIdentitySupported || computer.ServicePrincipalNames.State != AttributePartial || !bytes.Equal(computer.Certificates.Values[0].Bytes(), []byte{0, 255, 1}) {
		t.Fatal(computer, err)
	}
	entry.Attributes["objectclass"] = append(entry.Attributes["objectclass"], []byte("msDS-GroupManagedServiceAccount"))
	if _, err := decodeComputer(entry, DirectoryADDS); !errors.Is(err, ErrNotComputer) {
		t.Fatal(err)
	}
}

func TestComputerReadsLiteralIdentityFiltersAndLDSProjection(t *testing.T) {
	for _, kind := range []string{CapabilityActiveDirectory, CapabilityADLDS} {
		client := passwordTestClient(t, kind, passwordTestProtection, func(_ context.Context, query SearchOptions) (searchCursor, error) {
			if kind == CapabilityActiveDirectory && query.Filter != "(&(objectSid=*)(sAMAccountName=HOST$))" {
				t.Fatal(query.Filter)
			}
			entry := computerTestEntry(4096)
			if kind == CapabilityADLDS {
				entry.Attributes["objectclass"] = [][]byte{[]byte("top"), []byte("computer")}
				delete(entry.Attributes, "useraccountcontrol")
			}
			return objectTestCursor(entry), nil
		}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
			t.Fatal("read wrote")
			return ldapWriteAttempt{}
		})
		identity := objectTestIdentity()
		if kind == CapabilityActiveDirectory {
			identity, _ = IdentityByAccountName("HOST$")
		}
		result, err := client.Computer(context.Background(), identity, ResolveIdentityOptions{})
		if err != nil || result.Computer == nil || !result.Observation.Complete {
			t.Fatal(result, err)
		}
		if kind == CapabilityADLDS && result.Computer.AccountControl.StoredFlags != nil {
			t.Fatal("invented LDS account flags")
		}
	}
	permission := &LDAPError{Code: 50}
	client := objectTestClient(t, nil, func(_ context.Context, query SearchOptions) (searchCursor, error) {
		if !strings.Contains(query.Filter, "(objectClass=computer)") || !strings.Contains(query.Filter, "(!(objectClass=msDS-GroupManagedServiceAccount))") || !strings.Contains(query.Filter, "(location=東京)") {
			t.Fatal(query.Filter)
		}
		return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) {
			return []Object{computerTestEntry(4096)}, false, permission
		}, finish: func() error { return nil }}, nil
	}, nil)
	result, err := client.Computers(context.Background(), SearchOptions{Scope: ScopeSubtree, TypedFilter: FilterEqual("location", FilterText("東京"))})
	if !errors.Is(err, permission) || result.Observation.Complete || len(result.Computers) != 1 || len(result.Observation.Objects) != 1 {
		t.Fatal(result, err)
	}
}

func TestUpdateComputerPreservesFlagsAndOtherSPNs(t *testing.T) {
	for _, code := range []uint32{0, 19, 50} {
		reads, writes := 0, 0
		client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
			reads++
			flags, encryption := Flags32(0x40001002), Flags32(0x80000114)
			spns := [][]byte{[]byte("HOST/old"), []byte("HOST/keep")}
			if writes > 0 {
				flags, encryption = 0x40081000, 0x80000158
				spns = [][]byte{[]byte("HOST/new"), []byte("HOST/keep")}
			}
			entry := computerTestEntry(flags)
			entry.Attributes["msds-supportedencryptiontypes"] = [][]byte{[]byte(encryption.LDAPString())}
			entry.Attributes["serviceprincipalname"] = spns
			return objectTestCursor(entry), nil
		}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
			writes++
			mods := request.modifications
			if request.dn != objectGUIDTarget(objectTestGUID()) || len(mods) != 6 || mods[0].operation != 1 || mods[1].operation != 0 || string(mods[0].values[0]) != "HOST/old" || string(mods[1].values[0]) != "HOST/new" || mods[2].attribute != "userAccountControl" || string(mods[2].values[0]) != Flags32(0x40001002).LDAPString() || string(mods[3].values[0]) != Flags32(0x40081000).LDAPString() || mods[4].attribute != "msDS-SupportedEncryptionTypes" || string(mods[5].values[0]) != Flags32(0x80000158).LDAPString() {
				t.Fatal(request)
			}
			if code != 0 {
				return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: code, Diagnostic: "private SPN diagnostic"}}
			}
			return ldapWriteAttempt{State: ldapWriteAccepted}
		})
		enabled, delegated, compound := true, true, true
		encryption := Flags32(0x18)
		result, err := client.UpdateComputer(context.Background(), UpdateComputerRequest{Identity: objectTestIdentity(), Control: AccountControlPatch{Enabled: &enabled, TrustedForDelegation: &delegated}, Properties: ComputerProperties{KerberosEncryptionTypes: &encryption, CompoundIdentitySupported: &compound}, Changes: []AttributeChange{{Attribute: "servicePrincipalName", Kind: AttributeAddValues, Values: []RawValue{NewRawValue([]byte("HOST/new"))}}, {Attribute: "servicePrincipalName", Kind: AttributeRemoveValues, Values: []RawValue{NewRawValue([]byte("HOST/old"))}}}})
		if writes != 1 {
			t.Fatal(writes)
		}
		if code == 0 {
			if err != nil || !result.Mutation.Verified || result.Computer == nil || len(result.Computer.ServicePrincipalNames.Values) != 2 {
				t.Fatal(result, err)
			}
		} else {
			var native *LDAPError
			if !errors.As(err, &native) || native.Code != code || reads != 1 || result.Mutation.State != ObjectWriteRejected || native.Diagnostic != "private SPN diagnostic" || strings.Contains(err.Error(), "private SPN diagnostic") {
				t.Fatal(result, err)
			}
		}
	}
}

func TestUpdateComputerNoOpMissingFlagsAndRawConflicts(t *testing.T) {
	for _, missing := range []bool{false, true} {
		client := objectTestClient(t, nil, func(_ context.Context, query SearchOptions) (searchCursor, error) {
			entry := computerTestEntry(4096)
			entry.RequestedProperties = slices.Clone(query.Properties)
			if slices.Contains(query.Properties, "employeeID") {
				entry.Attributes["employeeid"] = [][]byte{[]byte("42")}
			}
			if !missing {
				entry.Attributes["msds-supportedencryptiontypes"] = [][]byte{[]byte("24")}
			}
			return objectTestCursor(entry), nil
		}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
			t.Fatal("no-op or unavailable flags wrote")
			return ldapWriteAttempt{}
		})
		encryption := Flags32(24)
		result, err := client.UpdateComputer(context.Background(), UpdateComputerRequest{Identity: objectTestIdentity(), Properties: ComputerProperties{KerberosEncryptionTypes: &encryption}, Options: ObjectMutationOptions{Properties: []string{"employeeID"}}})
		if missing {
			if !errors.Is(err, ErrAttributeUnavailable) || result.Mutation.State != ObjectWriteNotAttempted {
				t.Fatal(result, err)
			}
		} else {
			if err != nil || !result.Mutation.Verified || result.Computer == nil {
				t.Fatal(result, err)
			}
			value, e := result.Computer.Raw.Values("employeeID").Single()
			if e != nil || string(value.Bytes()) != "42" {
				t.Fatal(value, e)
			}
		}
	}
	name := "HOST"
	description := "new"
	for _, attribute := range []string{"sAMAccountName", "unicodePwd", "userAccountControl", "msDS-SupportedEncryptionTypes", "pwdLastSet", "description"} {
		_, err := computerAttributeChanges(ComputerProperties{SAMAccountName: &name, Description: &description}, []AttributeChange{{Attribute: attribute, Kind: AttributeClear}})
		if err == nil {
			changes, _ := computerAttributeChanges(ComputerProperties{Description: &description}, []AttributeChange{{Attribute: attribute, Kind: AttributeClear}})
			_, err = objectChanges(changes)
		}
		if err == nil {
			t.Fatal("accepted managed or conflicting attribute", attribute)
		}
	}
}

func TestComputerWriteCapabilityClassAndUncertainty(t *testing.T) {
	for _, mode := range []string{"lds", "user", "msa", "uncertain"} {
		reads, writes := 0, 0
		kind := CapabilityActiveDirectory
		if mode == "lds" {
			kind = CapabilityADLDS
		}
		client := passwordTestClient(t, kind, passwordTestProtection, func(context.Context, SearchOptions) (searchCursor, error) {
			reads++
			entry := computerTestEntry(4096)
			if mode == "user" {
				entry = userTestEntry(512)
			}
			if mode == "msa" {
				entry.Attributes["objectclass"] = append(entry.Attributes["objectclass"], []byte("msDS-ManagedServiceAccount"))
			}
			return objectTestCursor(entry), nil
		}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
			writes++
			return ldapWriteAttempt{State: ldapWriteUncertain, Err: errLDAPWriteUncertain}
		})
		location := "London"
		result, err := client.UpdateComputer(context.Background(), UpdateComputerRequest{Identity: objectTestIdentity(), Properties: ComputerProperties{Location: &location}})
		if mode == "uncertain" {
			if !errors.Is(err, ErrObjectWriteUncertain) || writes != 1 || reads != 1 || result.Mutation.State != ObjectWriteUncertain {
				t.Fatal(result, err)
			}
		} else if writes != 0 || err == nil {
			t.Fatal(mode, result, err)
		}
	}
}

func TestUpdateComputerPasswordTimestampInstructionVerification(t *testing.T) {
	for _, timestamp := range []string{"0", "-1", "1234"} {
		writes := 0
		client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
			entry := computerTestEntry(4096)
			if writes != 0 {
				entry.Attributes["pwdlastset"] = [][]byte{[]byte(timestamp)}
			}
			return objectTestCursor(entry), nil
		}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
			writes++
			if len(request.modifications) != 1 || request.modifications[0].attribute != "pwdLastSet" || string(request.modifications[0].values[0]) != "-1" {
				t.Fatal(request)
			}
			return ldapWriteAttempt{State: ldapWriteAccepted}
		})
		change := false
		result, err := client.UpdateComputer(context.Background(), UpdateComputerRequest{Identity: objectTestIdentity(), Control: AccountControlPatch{ChangePasswordAtLogon: &change}})
		if writes != 1 || result.Mutation.State != ObjectWriteAccepted || result.Mutation.Verified != (timestamp == "1234") || (err == nil) != (timestamp == "1234") {
			t.Fatal(result, err)
		}
	}
}

func TestDeleteComputerExplicitRecursivePartialOutcome(t *testing.T) {
	for _, recursive := range []bool{false, true} {
		writes := 0
		client := objectTestClient(t, []string{objectTreeDeleteControl}, func(context.Context, SearchOptions) (searchCursor, error) {
			return objectTestCursor(computerTestEntry(4096)), nil
		}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
			writes++
			if request.operation != ldapWriteDelete || request.dn != objectGUIDTarget(objectTestGUID()) {
				t.Fatal(request)
			}
			code := uint32(66)
			if recursive {
				code = 11
				if len(request.controls) != 1 || request.controls[0].oid != objectTreeDeleteControl || !request.controls[0].critical {
					t.Fatal(request)
				}
			} else if len(request.controls) != 0 {
				t.Fatal(request)
			}
			return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: code}}
		})
		result, err := client.DeleteComputer(context.Background(), DeleteComputerRequest{Identity: objectTestIdentity(), Recursive: recursive})
		if err == nil || writes != 1 || result.Mutation.State != ObjectWriteRejected || result.Mutation.PartialEffectsPossible != recursive {
			t.Fatal(result, err)
		}
		if !recursive && !errors.Is(err, ErrObjectNotLeaf) {
			t.Fatal(err)
		}
	}
}

type computerCreationFixture struct {
	entry    Object
	stages   []string
	password bool
}

func newComputerCreationFixture(t *testing.T, mode string) (*Client, *computerCreationFixture) {
	t.Helper()
	fixture := &computerCreationFixture{}
	client := passwordTestClient(t, CapabilityActiveDirectory, passwordTestProtection, func(_ context.Context, query SearchOptions) (searchCursor, error) {
		if strings.Contains(query.Filter, "classSchema") {
			return objectTestCursor(Object{Attributes: map[string][][]byte{"rdnattid": {[]byte("cn")}, "objectclasscategory": {[]byte("1")}}}), nil
		}
		if fixture.entry.DistinguishedName == "" {
			return objectTestCursor(objectTestEntry("OU=Computers,DC=example")), nil
		}
		if mode == "readback" && len(fixture.stages) == 1 {
			return nil, &LDAPError{Code: 50}
		}
		entry := fixture.entry
		entry.Attributes = make(map[string][][]byte, len(fixture.entry.Attributes))
		for name, values := range fixture.entry.Attributes {
			for _, value := range values {
				entry.Attributes[name] = append(entry.Attributes[name], slices.Clone(value))
			}
		}
		return objectTestCursor(entry), nil
	}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
		if request.operation == ldapWriteAdd {
			fixture.stages = append(fixture.stages, "create")
			if mode == "duplicate" {
				return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 68}}
			}
			if mode == "create uncertain" {
				return ldapWriteAttempt{State: ldapWriteUncertain, Err: errLDAPWriteUncertain}
			}
			fixture.entry = objectTestEntry(request.dn)
			for _, mod := range request.modifications {
				fixture.entry.Attributes[strings.ToLower(mod.attribute)] = mod.values
			}
			fixture.entry.Attributes["objectclass"] = append(fixture.entry.Attributes["objectclass"], []byte("user"))
			fixture.entry.Attributes["name"] = fixture.entry.Attributes["cn"]
			flags, _ := fixture.entry.Values("userAccountControl").Single()
			mask, _ := flags.Flags32()
			if !mask.Has(0x1000|2) || mask.Has(512) {
				t.Fatal("not disabled workstation account", mask)
			}
			if string(fixture.entry.Attributes["samaccountname"][0]) != "HOST$" {
				t.Fatal("SAM suffix lost")
			}
			return ldapWriteAttempt{State: ldapWriteAccepted}
		}
		if request.modifications[0].attribute == "unicodePwd" {
			fixture.stages = append(fixture.stages, "password")
			if mode == "password denied" {
				return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 19}}
			}
			if mode == "password uncertain" {
				return ldapWriteAttempt{State: ldapWriteUncertain, Err: errLDAPWriteUncertain}
			}
			fixture.password = true
			fixture.entry.Attributes["pwdlastset"] = [][]byte{[]byte("1234")}
			return ldapWriteAttempt{State: ldapWriteAccepted}
		}
		fixture.stages = append(fixture.stages, "enable")
		if !fixture.password && mode != "password not required" {
			t.Fatal("enabled before password")
		}
		if mode == "enable denied" {
			return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 50}}
		}
		for _, mod := range request.modifications {
			if mod.operation == 0 {
				fixture.entry.Attributes[strings.ToLower(mod.attribute)] = mod.values
			}
		}
		return ldapWriteAttempt{State: ldapWriteAccepted}
	})
	session := client.session.(passwordTestSession)
	base := session.base
	session.base = func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
		attributes, err := base(ctx, dn, properties)
		if dn == "" {
			attributes["schemanamingcontext"] = [][]byte{[]byte("CN=Schema,CN=Configuration,DC=example")}
		}
		return attributes, err
	}
	client.session = session
	return client, fixture
}

func TestCreateComputerStagesRetainFailuresWithoutReplay(t *testing.T) {
	for _, mode := range []string{"success", "duplicate", "create uncertain", "readback", "password denied", "password uncertain", "enable denied", "password not required", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			client, fixture := newComputerCreationFixture(t, mode)
			parent, _ := IdentityByDN("OU=Computers,DC=example")
			enabled, sam := true, "HOST"
			request := CreateComputerRequest{Parent: parent, Name: "東京, server", Properties: ComputerProperties{SAMAccountName: &sam}, Control: AccountControlPatch{Enabled: &enabled}, InitialPassword: []byte("PUBLIC-computer-password")}
			if mode == "password not required" {
				request.Control.PasswordNotRequired = &enabled
				request.InitialPassword = nil
			}
			if mode == "disabled" {
				request.Control.Enabled = nil
			}
			result, err := client.CreateComputer(context.Background(), request)
			want := []string{"create", "password", "enable"}
			switch mode {
			case "duplicate", "create uncertain", "readback":
				want = []string{"create"}
			case "password denied", "password uncertain", "disabled":
				want = []string{"create", "password"}
			case "password not required":
				want = []string{"create", "enable"}
			}
			if !reflect.DeepEqual(fixture.stages, want) {
				t.Fatal(fixture.stages, want, result, err)
			}
			if mode == "success" || mode == "password not required" || mode == "disabled" {
				if err != nil || !result.Complete || result.Computer == nil {
					t.Fatal(result, err)
				}
				if mode == "disabled" && (result.Enable != nil || result.Observation == nil || *result.Computer.AccountControl.Enabled) {
					t.Fatal(result)
				}
			} else {
				if !errors.Is(err, ErrComputerCreationIncomplete) || result.Complete {
					t.Fatal(result, err)
				}
				if mode != "duplicate" && mode != "create uncertain" && result.Creation.State != ObjectWriteAccepted {
					t.Fatal("accepted Add lost", result)
				}
				if mode == "password uncertain" && (result.Password == nil || result.Password.State != ObjectWriteUncertain || result.Enable != nil) {
					t.Fatal(result)
				}
			}
			if request.InitialPassword != nil && !bytes.Equal(request.InitialPassword, []byte("PUBLIC-computer-password")) {
				t.Fatal("caller password mutated")
			}
		})
	}
}

func TestCreateComputerDefaultsProtectionAndRedaction(t *testing.T) {
	client, fixture := newComputerCreationFixture(t, "disabled")
	parent, _ := IdentityByDN("OU=Computers,DC=example")
	result, err := client.CreateComputer(context.Background(), CreateComputerRequest{Parent: parent, Name: "HOST"})
	if err != nil || !result.Complete || result.Password != nil || result.Enable != nil || !reflect.DeepEqual(fixture.stages, []string{"create"}) || result.Computer == nil || *result.Computer.AccountControl.Enabled || *result.Computer.AccountControl.PasswordNotRequired {
		t.Fatal(result, err)
	}
	for _, mode := range []string{"implicit exemption", "insecure", "lds"} {
		client, fixture := newComputerCreationFixture(t, "success")
		request := CreateComputerRequest{Parent: parent, Name: "HOST", InitialPassword: []byte("PUBLIC-password")}
		session := client.session.(passwordTestSession)
		if mode == "implicit exemption" {
			yes := true
			request.Control.Enabled = &yes
			request.InitialPassword = nil
		}
		if mode == "insecure" {
			session.protect = func(context.Context, Transport) (PasswordProtection, error) {
				return PasswordProtection{Transport: client.config.Transport, CipherBits: 56}, nil
			}
		}
		if mode == "lds" {
			base := session.base
			session.base = func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
				attributes, err := base(ctx, dn, properties)
				if dn == "" {
					attributes["supportedcapabilities"] = [][]byte{[]byte(CapabilityADLDS)}
				}
				return attributes, err
			}
		}
		client.session = session
		result, err := client.CreateComputer(context.Background(), request)
		if err == nil || result.Creation.State != ObjectWriteNotAttempted || len(fixture.stages) != 0 {
			t.Fatal(mode, result, err)
		}
	}
	request := CreateComputerRequest{InitialPassword: []byte("PUBLIC-password")}
	encoded, err := json.Marshal(request)
	if err != nil || string(encoded) != `{"redacted":true}` || strings.Contains(fmt.Sprintf("%+v %#v", request, request), "PUBLIC") {
		t.Fatal("password redaction failed")
	}
}

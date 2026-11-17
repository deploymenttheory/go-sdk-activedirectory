package acceptance

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

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_computers "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/computers"
)

func InternalComputerTestEntry(flags admodel.Flags32) admodel.Object {
	entry := InternalUserTestEntry(flags)
	entry.Attributes["objectclass"] = append(entry.Attributes["objectclass"], []byte("computer"))
	entry.Attributes["samaccountname"] = [][]byte{[]byte("HOST$")}
	entry.Attributes["pwdlastset"] = [][]byte{[]byte("1234")}
	return entry
}

func TestComputerSAMAndTypedMapping(t *testing.T) {
	for _, name := range []string{"HOST", "HOST$", "HOST$$", "$", "", "李", "a\x00b"} {
		got, err := admodel.InternalComputerSAM(name)
		invalid := name == "HOST$$" || name == "$" || name == "" || strings.ContainsRune(name, 0)
		if invalid {
			if !errors.Is(err, admodel.ErrInvalidComputer) {
				t.Fatal(name, got, err)
			}
		} else if err != nil || got != strings.TrimSuffix(name, "$")+"$" {
			t.Fatal(name, got, err)
		}
	}
	entry := InternalComputerTestEntry(0x40081000)
	entry.Attributes["dnshostname"] = [][]byte{[]byte("host.example.test")}
	entry.Attributes["operatingsystem"] = [][]byte{[]byte("Windows Server 2025")}
	entry.Attributes["location"] = [][]byte{[]byte("東京")}
	entry.Attributes["accountexpires"] = [][]byte{[]byte("9223372036854775807")}
	entry.Attributes["msds-supportedencryptiontypes"] = [][]byte{[]byte("-2147483304")}
	entry.Attributes["serviceprincipalname;range=0-0"] = [][]byte{[]byte("HOST/a")}
	entry.Attributes["usercertificate"] = [][]byte{{0, 255, 1}}
	entry.RequestedProperties = admodel.InternalComputerProperties(nil)
	computer, err := admodel.InternalDecodeComputer(entry, admodel.DirectoryADDS)
	if err != nil || computer.DNSHostName == nil || *computer.DNSHostName != "host.example.test" ||
		computer.Location == nil ||
		*computer.Location != "東京" ||
		computer.AccountExpires == nil ||
		uint64(*computer.AccountExpires) != 9223372036854775807 ||
		computer.AccountControl.Enabled == nil ||
		!*computer.AccountControl.Enabled ||
		computer.AccountControl.TrustedForDelegation == nil ||
		!*computer.AccountControl.TrustedForDelegation ||
		computer.SupportedEncryptionTypes == nil ||
		*computer.SupportedEncryptionTypes != 0x80000158 ||
		*computer.KerberosEncryptionTypes != 0x18 ||
		!*computer.CompoundIdentitySupported ||
		computer.ServicePrincipalNames.State != admodel.AttributePartial ||
		!bytes.Equal(computer.Certificates.Values[0].Bytes(), []byte{0, 255, 1}) {
		t.Fatal(computer, err)
	}
	entry.Attributes["objectclass"] = append(
		entry.Attributes["objectclass"],
		[]byte("msDS-GroupManagedServiceAccount"),
	)
	if _, err := admodel.InternalDecodeComputer(
		entry,
		admodel.DirectoryADDS,
	); !errors.Is(
		err,
		admodel.ErrNotComputer,
	) {
		t.Fatal(err)
	}
}

func TestComputerReadsLiteralIdentityFiltersAndLDSProjection(t *testing.T) {
	for _, kind := range []string{admodel.CapabilityActiveDirectory, admodel.CapabilityADLDS} {
		client := InternalPasswordTestClient(
			t,
			kind,
			InternalPasswordTestProtection,
			func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				if kind == admodel.CapabilityActiveDirectory &&
					query.Filter != "(&(objectSid=*)(sAMAccountName=HOST$))" {
					t.Fatal(query.Filter)
				}
				entry := InternalComputerTestEntry(4096)
				if kind == admodel.CapabilityADLDS {
					entry.Attributes["objectclass"] = [][]byte{[]byte("top"), []byte("computer")}
					delete(entry.Attributes, "useraccountcontrol")
				}
				return InternalObjectTestCursor(entry), nil
			},
			func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				t.Fatal("read wrote")
				return admodel.InternalLdapWriteAttempt{}
			},
		)
		identity := InternalObjectTestIdentity()
		if kind == admodel.CapabilityActiveDirectory {
			identity, _ = admodel.IdentityByAccountName("HOST$")
		}
		result, err := adservice_computers.New(client).
			Computer(context.Background(), identity, admodel.ResolveIdentityOptions{})
		if err != nil || result.Computer == nil || !result.Observation.Complete {
			t.Fatal(result, err)
		}
		if kind == admodel.CapabilityADLDS && result.Computer.AccountControl.StoredFlags != nil {
			t.Fatal("invented LDS account flags")
		}
	}
	permission := &admodel.LDAPError{Code: 50}
	client := InternalObjectTestClient(
		t,
		nil,
		func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
			if !strings.Contains(query.Filter, "(objectClass=computer)") ||
				!strings.Contains(
					query.Filter,
					"(!(objectClass=msDS-GroupManagedServiceAccount))",
				) ||
				!strings.Contains(query.Filter, "(location=東京)") {
				t.Fatal(query.Filter)
			}
			return InternalTestSearchCursor{
				InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
					return []admodel.Object{InternalComputerTestEntry(4096)}, false, permission
				},
				InternalFinish: func() error { return nil },
			}, nil
		},
		nil,
	)
	result, err := adservice_computers.New(client).
		Computers(context.Background(), admodel.SearchOptions{Scope: admodel.ScopeSubtree, TypedFilter: admodel.FilterEqual("location", admodel.FilterText("東京"))})
	if !errors.Is(err, permission) || result.Observation.Complete || len(result.Computers) != 1 ||
		len(result.Observation.Objects) != 1 {
		t.Fatal(result, err)
	}
}

func TestUpdateComputerPreservesFlagsAndOtherSPNs(t *testing.T) {
	for _, code := range []uint32{0, 19, 50} {
		reads, writes := 0, 0
		client := InternalObjectTestClient(
			t,
			nil,
			func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				reads++
				flags, encryption := admodel.Flags32(0x40001002), admodel.Flags32(0x80000114)
				spns := [][]byte{[]byte("HOST/old"), []byte("HOST/keep")}
				if writes > 0 {
					flags, encryption = 0x40081000, 0x80000158
					spns = [][]byte{[]byte("HOST/new"), []byte("HOST/keep")}
				}
				entry := InternalComputerTestEntry(flags)
				entry.Attributes["msds-supportedencryptiontypes"] = [][]byte{
					[]byte(encryption.LDAPString()),
				}
				entry.Attributes["serviceprincipalname"] = spns
				return InternalObjectTestCursor(entry), nil
			},
			func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				writes++
				mods := request.InternalModifications
				if request.InternalDn != admodel.InternalObjectGUIDTarget(
					InternalObjectTestGUID(),
				) ||
					len(mods) != 6 ||
					mods[0].InternalOperation != 1 ||
					mods[1].InternalOperation != 0 ||
					string(mods[0].InternalValues[0]) != "HOST/old" ||
					string(mods[1].InternalValues[0]) != "HOST/new" ||
					mods[2].InternalAttribute != "userAccountControl" ||
					string(mods[2].InternalValues[0]) != admodel.Flags32(0x40001002).LDAPString() ||
					string(mods[3].InternalValues[0]) != admodel.Flags32(0x40081000).LDAPString() ||
					mods[4].InternalAttribute != "msDS-SupportedEncryptionTypes" ||
					string(mods[5].InternalValues[0]) != admodel.Flags32(0x80000158).LDAPString() {
					t.Fatal(request)
				}
				if code != 0 {
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteRejected,
						Err:   &admodel.LDAPError{Code: code, Diagnostic: "private SPN diagnostic"},
					}
				}
				return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
			},
		)
		enabled, delegated, compound := true, true, true
		encryption := admodel.Flags32(0x18)
		result, err := adservice_computers.New(client).
			UpdateComputer(context.Background(), admodel.UpdateComputerRequest{Identity: InternalObjectTestIdentity(), Control: admodel.AccountControlPatch{Enabled: &enabled, TrustedForDelegation: &delegated}, Properties: admodel.ComputerProperties{KerberosEncryptionTypes: &encryption, CompoundIdentitySupported: &compound}, Changes: []admodel.AttributeChange{{Attribute: "servicePrincipalName", Kind: admodel.AttributeAddValues, Values: []admodel.RawValue{admodel.NewRawValue([]byte("HOST/new"))}}, {Attribute: "servicePrincipalName", Kind: admodel.AttributeRemoveValues, Values: []admodel.RawValue{admodel.NewRawValue([]byte("HOST/old"))}}}})
		if writes != 1 {
			t.Fatal(writes)
		}
		if code == 0 {
			if err != nil || !result.Mutation.Verified || result.Computer == nil ||
				len(result.Computer.ServicePrincipalNames.Values) != 2 {
				t.Fatal(result, err)
			}
		} else {
			var native *admodel.LDAPError
			if !errors.As(err, &native) || native.Code != code || reads != 1 ||
				result.Mutation.State != admodel.ObjectWriteRejected ||
				native.Diagnostic != "private SPN diagnostic" ||
				strings.Contains(err.Error(), "private SPN diagnostic") {
				t.Fatal(result, err)
			}
		}
	}
}

func TestUpdateComputerNoOpMissingFlagsAndRawConflicts(t *testing.T) {
	for _, missing := range []bool{false, true} {
		client := InternalObjectTestClient(
			t,
			nil,
			func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				entry := InternalComputerTestEntry(4096)
				entry.RequestedProperties = slices.Clone(query.Properties)
				if slices.Contains(query.Properties, "employeeID") {
					entry.Attributes["employeeid"] = [][]byte{[]byte("42")}
				}
				if !missing {
					entry.Attributes["msds-supportedencryptiontypes"] = [][]byte{[]byte("24")}
				}
				return InternalObjectTestCursor(entry), nil
			},
			func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				t.Fatal("no-op or unavailable flags wrote")
				return admodel.InternalLdapWriteAttempt{}
			},
		)
		encryption := admodel.Flags32(24)
		result, err := adservice_computers.New(client).
			UpdateComputer(context.Background(), admodel.UpdateComputerRequest{Identity: InternalObjectTestIdentity(), Properties: admodel.ComputerProperties{KerberosEncryptionTypes: &encryption}, Options: admodel.ObjectMutationOptions{Properties: []string{"employeeID"}}})
		if missing {
			if !errors.Is(err, admodel.ErrAttributeUnavailable) ||
				result.Mutation.State != admodel.ObjectWriteNotAttempted {
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
		_, err := admodel.InternalComputerAttributeChanges(
			admodel.ComputerProperties{SAMAccountName: &name, Description: &description},
			[]admodel.AttributeChange{{Attribute: attribute, Kind: admodel.AttributeClear}},
		)
		if err == nil {
			changes, _ := admodel.InternalComputerAttributeChanges(
				admodel.ComputerProperties{Description: &description},
				[]admodel.AttributeChange{{Attribute: attribute, Kind: admodel.AttributeClear}},
			)
			_, err = admodel.InternalObjectChanges(changes)
		}
		if err == nil {
			t.Fatal("accepted managed or conflicting attribute", attribute)
		}
	}
}

func TestComputerWriteCapabilityClassAndUncertainty(t *testing.T) {
	for _, mode := range []string{"lds", "user", "msa", "uncertain"} {
		reads, writes := 0, 0
		kind := admodel.CapabilityActiveDirectory
		if mode == "lds" {
			kind = admodel.CapabilityADLDS
		}
		client := InternalPasswordTestClient(
			t,
			kind,
			InternalPasswordTestProtection,
			func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				reads++
				entry := InternalComputerTestEntry(4096)
				if mode == "user" {
					entry = InternalUserTestEntry(512)
				}
				if mode == "msa" {
					entry.Attributes["objectclass"] = append(
						entry.Attributes["objectclass"],
						[]byte("msDS-ManagedServiceAccount"),
					)
				}
				return InternalObjectTestCursor(entry), nil
			},
			func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				writes++
				return admodel.InternalLdapWriteAttempt{
					State: admodel.InternalLdapWriteUncertain,
					Err:   admodel.InternalLDAPWriteUncertainError(),
				}
			},
		)
		location := "London"
		result, err := adservice_computers.New(client).
			UpdateComputer(context.Background(), admodel.UpdateComputerRequest{Identity: InternalObjectTestIdentity(), Properties: admodel.ComputerProperties{Location: &location}})
		if mode == "uncertain" {
			if !errors.Is(err, admodel.ErrObjectWriteUncertain) || writes != 1 || reads != 1 ||
				result.Mutation.State != admodel.ObjectWriteUncertain {
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
		client := InternalObjectTestClient(
			t,
			nil,
			func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				entry := InternalComputerTestEntry(4096)
				if writes != 0 {
					entry.Attributes["pwdlastset"] = [][]byte{[]byte(timestamp)}
				}
				return InternalObjectTestCursor(entry), nil
			},
			func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				writes++
				if len(request.InternalModifications) != 1 ||
					request.InternalModifications[0].InternalAttribute != "pwdLastSet" ||
					string(request.InternalModifications[0].InternalValues[0]) != "-1" {
					t.Fatal(request)
				}
				return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
			},
		)
		change := false
		result, err := adservice_computers.New(client).
			UpdateComputer(context.Background(), admodel.UpdateComputerRequest{Identity: InternalObjectTestIdentity(), Control: admodel.AccountControlPatch{ChangePasswordAtLogon: &change}})
		if writes != 1 || result.Mutation.State != admodel.ObjectWriteAccepted ||
			result.Mutation.Verified != (timestamp == "1234") ||
			(err == nil) != (timestamp == "1234") {
			t.Fatal(result, err)
		}
	}
}

func TestDeleteComputerExplicitRecursivePartialOutcome(t *testing.T) {
	for _, recursive := range []bool{false, true} {
		writes := 0
		client := InternalObjectTestClient(
			t,
			[]string{admodel.InternalObjectTreeDeleteControl},
			func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				return InternalObjectTestCursor(InternalComputerTestEntry(4096)), nil
			},
			func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				writes++
				if request.InternalOperation != admodel.InternalLdapWriteDelete ||
					request.InternalDn != admodel.InternalObjectGUIDTarget(
						InternalObjectTestGUID(),
					) {
					t.Fatal(request)
				}
				code := uint32(66)
				if recursive {
					code = 11
					if len(request.InternalControls) != 1 ||
						request.InternalControls[0].InternalOid != admodel.InternalObjectTreeDeleteControl ||
						!request.InternalControls[0].InternalCritical {
						t.Fatal(request)
					}
				} else if len(request.InternalControls) != 0 {
					t.Fatal(request)
				}
				return admodel.InternalLdapWriteAttempt{
					State: admodel.InternalLdapWriteRejected,
					Err:   &admodel.LDAPError{Code: code},
				}
			},
		)
		result, err := adservice_computers.New(client).
			DeleteComputer(context.Background(), admodel.DeleteComputerRequest{Identity: InternalObjectTestIdentity(), Recursive: recursive})
		if err == nil || writes != 1 || result.Mutation.State != admodel.ObjectWriteRejected ||
			result.Mutation.PartialEffectsPossible != recursive {
			t.Fatal(result, err)
		}
		if !recursive && !errors.Is(err, admodel.ErrObjectNotLeaf) {
			t.Fatal(err)
		}
	}
}

type InternalComputerCreationFixture struct {
	InternalEntry    admodel.Object
	InternalStages   []string
	InternalPassword bool
}

func InternalNewComputerCreationFixture(
	t *testing.T,
	mode string,
) (*adengine.Client, *InternalComputerCreationFixture) {
	t.Helper()
	fixture := &InternalComputerCreationFixture{}
	client := InternalPasswordTestClient(
		t,
		admodel.CapabilityActiveDirectory,
		InternalPasswordTestProtection,
		func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
			if strings.Contains(query.Filter, "classSchema") {
				return InternalObjectTestCursor(
					admodel.Object{
						Attributes: map[string][][]byte{
							"rdnattid":            {[]byte("cn")},
							"objectclasscategory": {[]byte("1")},
						},
					},
				), nil
			}
			if fixture.InternalEntry.DistinguishedName == "" {
				return InternalObjectTestCursor(
					InternalObjectTestEntry("OU=Computers,DC=example"),
				), nil
			}
			if mode == "readback" && len(fixture.InternalStages) == 1 {
				return nil, &admodel.LDAPError{Code: 50}
			}
			entry := fixture.InternalEntry
			entry.Attributes = make(map[string][][]byte, len(fixture.InternalEntry.Attributes))
			for name, values := range fixture.InternalEntry.Attributes {
				for _, value := range values {
					entry.Attributes[name] = append(entry.Attributes[name], slices.Clone(value))
				}
			}
			return InternalObjectTestCursor(entry), nil
		},
		func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
			if request.InternalOperation == admodel.InternalLdapWriteAdd {
				fixture.InternalStages = append(fixture.InternalStages, "create")
				if mode == "duplicate" {
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteRejected,
						Err:   &admodel.LDAPError{Code: 68},
					}
				}
				if mode == "create uncertain" {
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteUncertain,
						Err:   admodel.InternalLDAPWriteUncertainError(),
					}
				}
				fixture.InternalEntry = InternalObjectTestEntry(request.InternalDn)
				for _, mod := range request.InternalModifications {
					fixture.InternalEntry.Attributes[strings.ToLower(mod.InternalAttribute)] = mod.InternalValues
				}
				fixture.InternalEntry.Attributes["objectclass"] = append(
					fixture.InternalEntry.Attributes["objectclass"],
					[]byte("user"),
				)
				fixture.InternalEntry.Attributes["name"] = fixture.InternalEntry.Attributes["cn"]
				flags, _ := fixture.InternalEntry.Values("userAccountControl").Single()
				mask, _ := flags.Flags32()
				if !mask.Has(0x1000|2) || mask.Has(512) {
					t.Fatal("not disabled workstation account", mask)
				}
				if string(fixture.InternalEntry.Attributes["samaccountname"][0]) != "HOST$" {
					t.Fatal("SAM suffix lost")
				}
				return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
			}
			if request.InternalModifications[0].InternalAttribute == "unicodePwd" {
				fixture.InternalStages = append(fixture.InternalStages, "password")
				if mode == "password denied" {
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteRejected,
						Err:   &admodel.LDAPError{Code: 19},
					}
				}
				if mode == "password uncertain" {
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteUncertain,
						Err:   admodel.InternalLDAPWriteUncertainError(),
					}
				}
				fixture.InternalPassword = true
				fixture.InternalEntry.Attributes["pwdlastset"] = [][]byte{[]byte("1234")}
				return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
			}
			fixture.InternalStages = append(fixture.InternalStages, "enable")
			if !fixture.InternalPassword && mode != "password not required" {
				t.Fatal("enabled before password")
			}
			if mode == "enable denied" {
				return admodel.InternalLdapWriteAttempt{
					State: admodel.InternalLdapWriteRejected,
					Err:   &admodel.LDAPError{Code: 50},
				}
			}
			for _, mod := range request.InternalModifications {
				if mod.InternalOperation == 0 {
					fixture.InternalEntry.Attributes[strings.ToLower(mod.InternalAttribute)] = mod.InternalValues
				}
			}
			return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
		},
	)
	session := adengine.InternalClientSession(client).(InternalPasswordTestSession)
	base := session.InternalBase
	session.InternalBase = func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
		attributes, err := base(ctx, dn, properties)
		if dn == "" {
			attributes["schemanamingcontext"] = [][]byte{
				[]byte("CN=Schema,CN=Configuration,DC=example"),
			}
		}
		return attributes, err
	}
	(*adengine.InternalClientSessionPointer(client)) = session
	return client, fixture
}

func TestCreateComputerStagesRetainFailuresWithoutReplay(t *testing.T) {
	for _, mode := range []string{"success", "duplicate", "create uncertain", "readback", "password denied", "password uncertain", "enable denied", "password not required", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			client, fixture := InternalNewComputerCreationFixture(t, mode)
			parent, _ := admodel.IdentityByDN("OU=Computers,DC=example")
			enabled, sam := true, "HOST"
			request := admodel.CreateComputerRequest{
				Parent:          parent,
				Name:            "東京, server",
				Properties:      admodel.ComputerProperties{SAMAccountName: &sam},
				Control:         admodel.AccountControlPatch{Enabled: &enabled},
				InitialPassword: []byte("PUBLIC-computer-password"),
			}
			if mode == "password not required" {
				request.Control.PasswordNotRequired = &enabled
				request.InitialPassword = nil
			}
			if mode == "disabled" {
				request.Control.Enabled = nil
			}
			result, err := adservice_computers.New(client).
				CreateComputer(context.Background(), request)
			want := []string{"create", "password", "enable"}
			switch mode {
			case "duplicate", "create uncertain", "readback":
				want = []string{"create"}
			case "password denied", "password uncertain", "disabled":
				want = []string{"create", "password"}
			case "password not required":
				want = []string{"create", "enable"}
			}
			if !reflect.DeepEqual(fixture.InternalStages, want) {
				t.Fatal(fixture.InternalStages, want, result, err)
			}
			if mode == "success" || mode == "password not required" || mode == "disabled" {
				if err != nil || !result.Complete || result.Computer == nil {
					t.Fatal(result, err)
				}
				if mode == "disabled" &&
					(result.Enable != nil || result.Observation == nil || *result.Computer.AccountControl.Enabled) {
					t.Fatal(result)
				}
			} else {
				// A duplicate name is rejected with nothing written, so it must
				// report as already-exists rather than as a partly finished
				// creation; every other failure here did reach the directory.
				if mode == "duplicate" {
					if errors.Is(err, admodel.ErrComputerCreationIncomplete) ||
						!admodel.IsAlreadyExists(err) ||
						result.Complete {
						t.Fatal(result, err)
					}
				} else if !errors.Is(err, admodel.ErrComputerCreationIncomplete) || result.Complete {
					t.Fatal(result, err)
				}
				if mode != "duplicate" && mode != "create uncertain" &&
					result.Creation.State != admodel.ObjectWriteAccepted {
					t.Fatal("accepted Add lost", result)
				}
				if mode == "password uncertain" &&
					(result.Password == nil || result.Password.State != admodel.ObjectWriteUncertain || result.Enable != nil) {
					t.Fatal(result)
				}
			}
			if request.InitialPassword != nil &&
				!bytes.Equal(request.InitialPassword, []byte("PUBLIC-computer-password")) {
				t.Fatal("caller password mutated")
			}
		})
	}
}

func TestCreateComputerDefaultsProtectionAndRedaction(t *testing.T) {
	client, fixture := InternalNewComputerCreationFixture(t, "disabled")
	parent, _ := admodel.IdentityByDN("OU=Computers,DC=example")
	result, err := adservice_computers.New(client).
		CreateComputer(context.Background(), admodel.CreateComputerRequest{Parent: parent, Name: "HOST"})
	if err != nil || !result.Complete || result.Password != nil || result.Enable != nil ||
		!reflect.DeepEqual(fixture.InternalStages, []string{"create"}) ||
		result.Computer == nil ||
		*result.Computer.AccountControl.Enabled ||
		*result.Computer.AccountControl.PasswordNotRequired {
		t.Fatal(result, err)
	}
	for _, mode := range []string{"implicit exemption", "insecure", "lds"} {
		client, fixture := InternalNewComputerCreationFixture(t, "success")
		request := admodel.CreateComputerRequest{
			Parent:          parent,
			Name:            "HOST",
			InitialPassword: []byte("PUBLIC-password"),
		}
		session := adengine.InternalClientSession(client).(InternalPasswordTestSession)
		if mode == "implicit exemption" {
			yes := true
			request.Control.Enabled = &yes
			request.InitialPassword = nil
		}
		if mode == "insecure" {
			session.InternalProtect = func(context.Context, admodel.Transport) (admodel.PasswordProtection, error) {
				return admodel.PasswordProtection{
					Transport:  adengine.InternalClientConfig(client).Transport,
					CipherBits: 56,
				}, nil
			}
		}
		if mode == "lds" {
			base := session.InternalBase
			session.InternalBase = func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
				attributes, err := base(ctx, dn, properties)
				if dn == "" {
					attributes["supportedcapabilities"] = [][]byte{[]byte(admodel.CapabilityADLDS)}
				}
				return attributes, err
			}
		}
		(*adengine.InternalClientSessionPointer(client)) = session
		result, err := adservice_computers.New(client).CreateComputer(context.Background(), request)
		if err == nil || result.Creation.State != admodel.ObjectWriteNotAttempted ||
			len(fixture.InternalStages) != 0 {
			t.Fatal(mode, result, err)
		}
	}
	request := admodel.CreateComputerRequest{InitialPassword: []byte("PUBLIC-password")}
	encoded, err := json.Marshal(request)
	if err != nil || string(encoded) != `{"redacted":true}` ||
		strings.Contains(fmt.Sprintf("%+v %#v", request, request), "PUBLIC") {
		t.Fatal("password redaction failed")
	}
}

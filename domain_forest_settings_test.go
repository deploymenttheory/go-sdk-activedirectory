package activedirectory

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

const settingsPartitions = "CN=Partitions," + operationTestConfig

type settingsFixture struct {
	objects      map[string]map[string][][]byte
	writes       []ldapWriteRequest
	attempt      ldapWriteAttempt
	searchErr    error
	featureError error
	write        func(context.Context, ldapWriteRequest) ldapWriteAttempt
}

func newSettingsFixture() *settingsFixture {
	objects, locations, _ := operationMasterFixture()
	for _, dn := range locations {
		objects[dn]["fsmoroleowner"] = [][]byte{[]byte(operationTestTarget)}
	}
	root := objects[""]
	root["namingcontexts"] = [][]byte{[]byte(operationTestDomain), []byte(operationTestConfig), []byte(operationTestSchema)}
	root["rootdomainnamingcontext"] = [][]byte{[]byte(operationTestDomain)}
	root["domainfunctionality"], root["forestfunctionality"], root["domaincontrollerfunctionality"] = [][]byte{[]byte("6")}, [][]byte{[]byte("6")}, [][]byte{[]byte("7")}
	objects[operationTestSchema]["objectversion"] = [][]byte{[]byte("91")}
	objects[operationTestDomain]["objectguid"] = [][]byte{objectTestGUID().Bytes()}
	other, _ := ParseGUID("11223344-5566-7788-99aa-bbccddeeff00")
	objects[settingsPartitions]["objectguid"] = [][]byte{other.Bytes()}
	for _, dn := range []string{operationTestDomain, settingsPartitions} {
		objects[dn]["msds-behavior-version"] = [][]byte{[]byte("6")}
		objects[dn]["ntmixeddomain"] = [][]byte{[]byte("0")}
	}
	objects[operationTestDomain]["description"] = [][]byte{[]byte("unrelated value")}
	objects[operationTestTarget]["msds-behavior-version"] = [][]byte{[]byte("7")}
	objects[operationTestTarget]["msds-hasdomainncs"] = [][]byte{[]byte(operationTestDomain)}
	objects["CN=example,"+settingsPartitions] = map[string][][]byte{"objectclass": {[]byte("crossRef")}, "ncname": {[]byte(operationTestDomain)}, "systemflags": {[]byte("3")}, "msds-behavior-version": {[]byte("7")}, "ntmixeddomain": {[]byte("0")}}
	return &settingsFixture{objects: objects, attempt: ldapWriteAttempt{State: ldapWriteAccepted}}
}

func (f *settingsFixture) session() objectWriteTestSession {
	return objectWriteTestSession{testSession: testSession{
		base: func(_ context.Context, dn string, properties []string) (map[string][][]byte, error) {
			attrs, ok := f.objects[dn]
			if !ok {
				return nil, &LDAPError{Code: 32}
			}
			return settingsProjection(attrs, properties), nil
		},
		search: func(_ context.Context, query SearchOptions) (searchCursor, error) {
			var found []Object
			for dn, attrs := range f.objects {
				if dn == "" {
					continue
				}
				match := false
				switch {
				case strings.Contains(query.Filter, "objectClass=msDS-OptionalFeature"):
					match = len(attrs["msds-enabledfeaturebl"]) != 0
				case strings.Contains(query.Filter, "systemFlags:"):
					match = len(attrs["ncname"]) != 0
				case strings.Contains(query.Filter, "objectClass=nTDSDSA"):
					match = len(attrs["msds-hasdomainncs"]) != 0
				case query.Scope == ScopeBase:
					match = sameSettingsDN(dn, query.Base)
				default:
					match = len(attrs["objectguid"]) == 1 && strings.Contains(query.Filter, identityBinaryLiteral(attrs["objectguid"][0]))
				}
				if match {
					found = append(found, Object{DistinguishedName: dn, Attributes: settingsProjection(attrs, query.Properties), RequestedProperties: query.Properties})
				}
			}
			err := f.searchErr
			if strings.Contains(query.Filter, "objectClass=msDS-OptionalFeature") {
				err = f.featureError
			}
			return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) { return found, true, err }, finish: func() error { return nil }}, nil
		}, finish: func() error { return nil },
	}, write: func(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
		f.writes = append(f.writes, request)
		attempt := f.attempt
		if f.write != nil {
			attempt = f.write(ctx, request)
		}
		if attempt.State == ldapWriteAccepted {
			for _, attrs := range f.objects {
				if len(attrs["objectguid"]) != 1 {
					continue
				}
				guid, _ := GUIDFromBytes(attrs["objectguid"][0])
				if request.dn != objectGUIDTarget(guid) {
					continue
				}
				for _, mod := range request.modifications {
					name := strings.ToLower(mod.attribute)
					switch mod.operation {
					case 2:
						attrs[name] = mod.values
					case 0:
						attrs[name] = append(attrs[name], mod.values...)
					case 1:
						if len(mod.values) == 0 {
							delete(attrs, name)
							continue
						}
						attrs[name] = slices.DeleteFunc(attrs[name], func(value []byte) bool {
							return slices.ContainsFunc(mod.values, func(removed []byte) bool { return slices.Equal(value, removed) })
						})
					}
				}
			}
		}
		return attempt
	}}
}

func settingsProjection(attrs map[string][][]byte, properties []string) map[string][][]byte {
	result := make(map[string][][]byte)
	for _, property := range properties {
		key := strings.ToLower(property)
		if values, ok := attrs[key]; ok {
			result[key] = make([][]byte, len(values))
			for i, value := range values {
				result[key][i] = slices.Clone(value)
			}
		}
	}
	return result
}

func (f *settingsFixture) client(t *testing.T) *Client {
	t.Helper()
	client := newClient(Config{Endpoint: Endpoint{Host: "dc.example.test", Port: 389}, Timeout: 5 * time.Second}, f.session())
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client
}

func settingsIdentity(forest bool) Identity {
	dn := operationTestDomain
	if forest {
		dn = settingsPartitions
	}
	identity, _ := IdentityByDN(dn)
	return identity
}

func TestUpdateDomainSettingsPreservesUnrelatedAndZero(t *testing.T) {
	f := newSettingsFixture()
	days := uint32(0)
	suffixes := []string{"example.test", "例子.test"}
	managed := `CN=Jörg\, 李,` + operationTestDomain
	result, err := f.client(t).UpdateDomain(context.Background(), UpdateDomainRequest{Identity: settingsIdentity(false), AllowedDNSSuffixes: &suffixes, LastLogonReplicationIntervalDays: &days, ManagedByDN: &managed, Changes: []AttributeChange{{Attribute: "extensionBinary", Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte{0, 255}), NewRawValue([]byte{})}}}})
	if err != nil || !result.Verified || result.State != ObjectWriteAccepted || len(f.writes) != 1 {
		t.Fatalf("%+v %v writes=%d", result, err, len(f.writes))
	}
	if len(f.writes[0].modifications) != 4 || string(f.objects[operationTestDomain]["msds-logontimesyncinterval"][0]) != "0" || string(f.objects[operationTestDomain]["description"][0]) != "unrelated value" {
		t.Fatal(f.writes, f.objects[operationTestDomain])
	}
}

func TestUpdateForestSettingsExactRemoveAddAndClear(t *testing.T) {
	f := newSettingsFixture()
	f.objects[settingsPartitions]["upnsuffixes"] = [][]byte{[]byte("old.test"), []byte("keep.test")}
	result, err := f.client(t).UpdateForest(context.Background(), UpdateForestRequest{Identity: settingsIdentity(true), Changes: []AttributeChange{{Attribute: "uPNSuffixes", Kind: AttributeAddValues, Values: []RawValue{NewRawValue([]byte("new.test"))}}, {Attribute: "uPNSuffixes", Kind: AttributeRemoveValues, Values: []RawValue{NewRawValue([]byte("old.test"))}}}})
	if err != nil || !result.Verified || len(f.writes) != 1 || f.writes[0].modifications[0].operation != 1 || !reflect.DeepEqual(f.objects[settingsPartitions]["upnsuffixes"], [][]byte{[]byte("keep.test"), []byte("new.test")}) {
		t.Fatal(result, err, f.writes)
	}
	empty := []string{}
	result, err = f.client(t).UpdateForest(context.Background(), UpdateForestRequest{Identity: settingsIdentity(true), UPNSuffixes: &empty})
	if !errors.Is(err, ErrObjectVerification) || result.State != ObjectWriteAccepted || result.Verified || !result.ReadbackComplete {
		t.Fatal("omission does not prove clear", result, err)
	}
}

func TestDirectorySettingsValidationBeforeIO(t *testing.T) {
	var client *Client
	days := uint32(0)
	for _, request := range []UpdateDomainRequest{
		{Identity: settingsIdentity(false)},
		{Identity: settingsIdentity(false), LastLogonReplicationIntervalDays: &days, Changes: []AttributeChange{directorySetting("msDS-LogonTimeSyncInterval", "1")}},
		{Identity: settingsIdentity(false), Changes: []AttributeChange{directorySetting("msDS-Behavior-Version", "7")}},
		{Identity: settingsIdentity(false), Changes: []AttributeChange{directorySetting("fSMORoleOwner", operationTestTarget)}},
	} {
		if _, err := client.UpdateDomain(context.Background(), request); err == nil || errors.Is(err, ErrClosed) {
			t.Fatal("invalid request reached I/O", err)
		}
	}
	if _, err := client.UpdateForest(context.Background(), UpdateForestRequest{Identity: settingsIdentity(true), Changes: []AttributeChange{directorySetting("description", "not a forest suffix")}}); !errors.Is(err, ErrInvalidDirectorySettings) {
		t.Fatal(err)
	}
}

func TestDirectorySettingsRejectsWrongTargetAndCapability(t *testing.T) {
	for _, kind := range []string{"LDS", "RODC", "GC", "wrong class", "cross domain", "rolling"} {
		t.Run(kind, func(t *testing.T) {
			f := newSettingsFixture()
			request := UpdateDomainRequest{Identity: settingsIdentity(false), Changes: []AttributeChange{directorySetting("description", "changed")}}
			switch kind {
			case "LDS":
				f.objects[""]["supportedcapabilities"] = [][]byte{[]byte(CapabilityADLDS)}
			case "RODC":
				f.objects[operationTestTarget]["msds-isrodc"] = [][]byte{[]byte("TRUE")}
			case "wrong class":
				f.objects[operationTestDomain]["objectclass"] = [][]byte{[]byte("container")}
			case "cross domain":
				f.objects[""]["defaultnamingcontext"] = [][]byte{[]byte("DC=elsewhere,DC=test")}
			case "rolling":
				value := true
				request.PublicKeyRequiredPasswordRolling = &value
			}
			client := f.client(t)
			if kind == "GC" {
				client.config.Endpoint.Port = 3268
			}
			result, err := client.UpdateDomain(context.Background(), request)
			if err == nil || result.State != ObjectWriteNotAttempted || len(f.writes) != 0 {
				t.Fatal(result, err, f.writes)
			}
		})
	}
}

package acceptance

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_directory_settings "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/directory_settings"
)

const InternalSettingsPartitions = "CN=Partitions," + InternalOperationTestConfig

type InternalSettingsFixture struct {
	InternalObjects      map[string]map[string][][]byte
	InternalWrites       []admodel.InternalLdapWriteRequest
	InternalAttempt      admodel.InternalLdapWriteAttempt
	InternalSearchErr    error
	InternalFeatureError error
	InternalWrite        func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt
}

func InternalNewSettingsFixture() *InternalSettingsFixture {
	objects, locations, _ := InternalOperationMasterFixture()
	for _, dn := range locations {
		objects[dn]["fsmoroleowner"] = [][]byte{[]byte(InternalOperationTestTarget)}
	}
	root := objects[""]
	root["namingcontexts"] = [][]byte{
		[]byte(InternalOperationTestDomain),
		[]byte(InternalOperationTestConfig),
		[]byte(InternalOperationTestSchema),
	}
	root["rootdomainnamingcontext"] = [][]byte{[]byte(InternalOperationTestDomain)}
	root["domainfunctionality"], root["forestfunctionality"], root["domaincontrollerfunctionality"] = [][]byte{
		[]byte("6"),
	}, [][]byte{
		[]byte("6"),
	}, [][]byte{
		[]byte("7"),
	}
	objects[InternalOperationTestSchema]["objectversion"] = [][]byte{[]byte("91")}
	objects[InternalOperationTestDomain]["objectguid"] = [][]byte{InternalObjectTestGUID().Bytes()}
	other, _ := admodel.ParseGUID("11223344-5566-7788-99aa-bbccddeeff00")
	objects[InternalSettingsPartitions]["objectguid"] = [][]byte{other.Bytes()}
	for _, dn := range []string{InternalOperationTestDomain, InternalSettingsPartitions} {
		objects[dn]["msds-behavior-version"] = [][]byte{[]byte("6")}
		objects[dn]["ntmixeddomain"] = [][]byte{[]byte("0")}
	}
	objects[InternalOperationTestDomain]["description"] = [][]byte{[]byte("unrelated value")}
	objects[InternalOperationTestTarget]["msds-behavior-version"] = [][]byte{[]byte("7")}
	objects[InternalOperationTestTarget]["msds-hasdomainncs"] = [][]byte{
		[]byte(InternalOperationTestDomain),
	}
	objects["CN=example,"+InternalSettingsPartitions] = map[string][][]byte{
		"objectclass":           {[]byte("crossRef")},
		"ncname":                {[]byte(InternalOperationTestDomain)},
		"systemflags":           {[]byte("3")},
		"msds-behavior-version": {[]byte("7")},
		"ntmixeddomain":         {[]byte("0")},
	}
	return &InternalSettingsFixture{
		InternalObjects: objects,
		InternalAttempt: admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted},
	}
}

func (f *InternalSettingsFixture) InternalSession() InternalObjectWriteTestSession {
	return InternalObjectWriteTestSession{InternalTestSession: InternalTestSession{
		InternalBase: func(_ context.Context, dn string, properties []string) (map[string][][]byte, error) {
			attrs, ok := f.InternalObjects[dn]
			if !ok {
				return nil, &admodel.LDAPError{Code: 32}
			}
			return InternalSettingsProjection(attrs, properties), nil
		},
		InternalSearch: func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
			var found []admodel.Object
			for dn, attrs := range f.InternalObjects {
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
				case query.Scope == admodel.ScopeBase:
					match = admodel.InternalSameSettingsDN(dn, query.Base)
				default:
					match = len(attrs["objectguid"]) == 1 &&
						strings.Contains(
							query.Filter,
							admodel.InternalIdentityBinaryLiteral(attrs["objectguid"][0]),
						)
				}
				if match {
					found = append(
						found,
						admodel.Object{
							DistinguishedName: dn,
							Attributes: InternalSettingsProjection(
								attrs,
								query.Properties,
							),
							RequestedProperties: query.Properties,
						},
					)
				}
			}
			err := f.InternalSearchErr
			if strings.Contains(query.Filter, "objectClass=msDS-OptionalFeature") {
				err = f.InternalFeatureError
			}
			return InternalTestSearchCursor{
				InternalRead:   func(context.Context, uint32) ([]admodel.Object, bool, error) { return found, true, err },
				InternalFinish: func() error { return nil },
			}, nil
		},
		InternalFinish: func() error { return nil },
	}, InternalWrite: func(ctx context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
		f.InternalWrites = append(f.InternalWrites, request)
		attempt := f.InternalAttempt
		if f.InternalWrite != nil {
			attempt = f.InternalWrite(ctx, request)
		}
		if attempt.State == admodel.InternalLdapWriteAccepted {
			for _, attrs := range f.InternalObjects {
				if len(attrs["objectguid"]) != 1 {
					continue
				}
				guid, _ := admodel.GUIDFromBytes(attrs["objectguid"][0])
				if request.InternalDn != admodel.InternalObjectGUIDTarget(guid) {
					continue
				}
				for _, mod := range request.InternalModifications {
					name := strings.ToLower(mod.InternalAttribute)
					switch mod.InternalOperation {
					case 2:
						attrs[name] = mod.InternalValues
					case 0:
						attrs[name] = append(attrs[name], mod.InternalValues...)
					case 1:
						if len(mod.InternalValues) == 0 {
							delete(attrs, name)
							continue
						}
						attrs[name] = slices.DeleteFunc(attrs[name], func(value []byte) bool {
							return slices.ContainsFunc(
								mod.InternalValues,
								func(removed []byte) bool { return slices.Equal(value, removed) },
							)
						})
					}
				}
			}
		}
		return attempt
	}}
}

func InternalSettingsProjection(
	attrs map[string][][]byte,
	properties []string,
) map[string][][]byte {
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

func (f *InternalSettingsFixture) InternalClient(t *testing.T) *adengine.Client {
	t.Helper()
	client := adengine.InternalNewClient(
		admodel.Config{
			Endpoint: admodel.Endpoint{Host: "dc.example.test", Port: 389},
			Timeout:  5 * time.Second,
		},
		f.InternalSession(),
	)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client
}

func InternalSettingsIdentity(forest bool) admodel.Identity {
	dn := InternalOperationTestDomain
	if forest {
		dn = InternalSettingsPartitions
	}
	identity, _ := admodel.IdentityByDN(dn)
	return identity
}

func TestUpdateDomainSettingsPreservesUnrelatedAndZero(t *testing.T) {
	f := InternalNewSettingsFixture()
	days := uint32(0)
	suffixes := []string{"example.test", "例子.test"}
	managed := `CN=Jörg\, 李,` + InternalOperationTestDomain
	result, err := adservice_directory_settings.New(f.InternalClient(t)).
		UpdateDomain(context.Background(), admodel.UpdateDomainRequest{Identity: InternalSettingsIdentity(false), AllowedDNSSuffixes: &suffixes, LastLogonReplicationIntervalDays: &days, ManagedByDN: &managed, Changes: []admodel.AttributeChange{{Attribute: "extensionBinary", Kind: admodel.AttributeSet, Values: []admodel.RawValue{admodel.NewRawValue([]byte{0, 255}), admodel.NewRawValue([]byte{})}}}})
	if err != nil || !result.Verified || result.State != admodel.ObjectWriteAccepted ||
		len(f.InternalWrites) != 1 {
		t.Fatalf("%+v %v writes=%d", result, err, len(f.InternalWrites))
	}
	if len(f.InternalWrites[0].InternalModifications) != 4 ||
		string(
			f.InternalObjects[InternalOperationTestDomain]["msds-logontimesyncinterval"][0],
		) != "0" ||
		string(
			f.InternalObjects[InternalOperationTestDomain]["description"][0],
		) != "unrelated value" {
		t.Fatal(f.InternalWrites, f.InternalObjects[InternalOperationTestDomain])
	}
}

func TestUpdateForestSettingsExactRemoveAddAndClear(t *testing.T) {
	f := InternalNewSettingsFixture()
	f.InternalObjects[InternalSettingsPartitions]["upnsuffixes"] = [][]byte{
		[]byte("old.test"),
		[]byte("keep.test"),
	}
	result, err := adservice_directory_settings.New(f.InternalClient(t)).
		UpdateForest(context.Background(), admodel.UpdateForestRequest{Identity: InternalSettingsIdentity(true), Changes: []admodel.AttributeChange{{Attribute: "uPNSuffixes", Kind: admodel.AttributeAddValues, Values: []admodel.RawValue{admodel.NewRawValue([]byte("new.test"))}}, {Attribute: "uPNSuffixes", Kind: admodel.AttributeRemoveValues, Values: []admodel.RawValue{admodel.NewRawValue([]byte("old.test"))}}}})
	if err != nil || !result.Verified || len(f.InternalWrites) != 1 ||
		f.InternalWrites[0].InternalModifications[0].InternalOperation != 1 ||
		!reflect.DeepEqual(
			f.InternalObjects[InternalSettingsPartitions]["upnsuffixes"],
			[][]byte{[]byte("keep.test"), []byte("new.test")},
		) {
		t.Fatal(result, err, f.InternalWrites)
	}
	empty := []string{}
	result, err = adservice_directory_settings.New(f.InternalClient(t)).
		UpdateForest(context.Background(), admodel.UpdateForestRequest{Identity: InternalSettingsIdentity(true), UPNSuffixes: &empty})
	if !errors.Is(err, admodel.ErrObjectUnverifiable) ||
		result.State != admodel.ObjectWriteAccepted ||
		result.Verified ||
		!result.ReadbackComplete {
		t.Fatal("omission does not prove clear", result, err)
	}
}

func TestDirectorySettingsValidationBeforeIO(t *testing.T) {
	var client *adengine.Client
	days := uint32(0)
	for _, request := range []admodel.UpdateDomainRequest{
		{Identity: InternalSettingsIdentity(false)},
		{Identity: InternalSettingsIdentity(false), LastLogonReplicationIntervalDays: &days, Changes: []admodel.AttributeChange{admodel.InternalDirectorySetting("msDS-LogonTimeSyncInterval", "1")}},
		{Identity: InternalSettingsIdentity(false), Changes: []admodel.AttributeChange{admodel.InternalDirectorySetting("msDS-Behavior-Version", "7")}},
		{Identity: InternalSettingsIdentity(false), Changes: []admodel.AttributeChange{admodel.InternalDirectorySetting("fSMORoleOwner", InternalOperationTestTarget)}},
	} {
		if _, err := adservice_directory_settings.New(client).
			UpdateDomain(context.Background(), request); err == nil ||
			errors.Is(err, admodel.ErrClosed) {
			t.Fatal("invalid request reached I/O", err)
		}
	}
	if _, err := adservice_directory_settings.New(client).
		UpdateForest(context.Background(), admodel.UpdateForestRequest{Identity: InternalSettingsIdentity(true), Changes: []admodel.AttributeChange{admodel.InternalDirectorySetting("description", "not a forest suffix")}}); !errors.Is(
		err,
		admodel.ErrInvalidDirectorySettings,
	) {
		t.Fatal(err)
	}
}

func TestDirectorySettingsRejectsWrongTargetAndCapability(t *testing.T) {
	for _, kind := range []string{"LDS", "RODC", "GC", "wrong class", "cross domain", "rolling"} {
		t.Run(kind, func(t *testing.T) {
			f := InternalNewSettingsFixture()
			request := admodel.UpdateDomainRequest{
				Identity: InternalSettingsIdentity(false),
				Changes: []admodel.AttributeChange{
					admodel.InternalDirectorySetting("description", "changed"),
				},
			}
			switch kind {
			case "LDS":
				f.InternalObjects[""]["supportedcapabilities"] = [][]byte{
					[]byte(admodel.CapabilityADLDS),
				}
			case "RODC":
				f.InternalObjects[InternalOperationTestTarget]["msds-isrodc"] = [][]byte{
					[]byte("TRUE"),
				}
			case "wrong class":
				f.InternalObjects[InternalOperationTestDomain]["objectclass"] = [][]byte{
					[]byte("container"),
				}
			case "cross domain":
				f.InternalObjects[""]["defaultnamingcontext"] = [][]byte{
					[]byte("DC=elsewhere,DC=test"),
				}
			case "rolling":
				value := true
				request.PublicKeyRequiredPasswordRolling = &value
			}
			client := f.InternalClient(t)
			if kind == "GC" {
				(*adengine.InternalClientConfigPointer(client)).Endpoint.Port = 3268
			}
			result, err := adservice_directory_settings.New(client).
				UpdateDomain(context.Background(), request)
			if err == nil || result.State != admodel.ObjectWriteNotAttempted ||
				len(f.InternalWrites) != 0 {
				t.Fatal(result, err, f.InternalWrites)
			}
		})
	}
}

package activedirectory

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestLegacyRestoreAtomicAttributesAndUnknownFeatureState(t *testing.T) {
	for _, kind := range []string{CapabilityActiveDirectory, CapabilityADLDS} {
		for _, mode := range []string{"unknown", "disabled", "enabled", "tombstone-recycled-flag", "unknown-recycled-flag", "feature-denied", "explicit-missing-metadata", "missing-mandatory", "wrong-readback", "ranged-readback", "recycled", "fallback-recycled", "protected", "nc-root", "schema", "naming-conflict"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				writes := 0
				identity, _ := IdentityByGUID(objectTestGUID().String())
				request := RestoreObjectRequest{Identity: identity, Mode: RestoreLegacyTombstone, Attributes: map[string][]RawValue{
					"sn": {NewRawValue([]byte("Required"))}, "description": {NewRawValue([]byte("one")), NewRawValue([]byte("two"))}, "userCertificate": {NewRawValue([]byte{0, 255, 128})},
				}}
				want := `cn=Jörg\, 李,OU=People,DC=example`
				if mode == "explicit-missing-metadata" {
					name := "Explicit"
					request.NewName = &name
					request.TargetParent, _ = IdentityByDN("OU=People,DC=example")
					want = "cn=Explicit,OU=People,DC=example"
				}
				if mode == "naming-conflict" {
					request.Attributes["CN"] = []RawValue{NewRawValue([]byte("different"))}
				}
				client := restorationTestClient(t, kind, func(_ context.Context, options SearchOptions) (searchCursor, error) {
					featureMode := "feature-hidden"
					if mode == "disabled" || mode == "tombstone-recycled-flag" {
						featureMode = "feature-disabled"
					}
					if mode == "enabled" || mode == "recycled" {
						featureMode = ""
					}
					if mode == "feature-denied" && options.Base == restorationDSA {
						return nil, &LDAPError{Code: 50}
					}
					if cursor, ok := restorationFeatureCursor(options, featureMode); ok {
						return cursor, nil
					}
					if options.Base == "OU=People,DC=example" {
						return objectTestCursor(objectTestEntry(options.Base)), nil
					}
					if writes != 1 || !slices.Contains(options.Properties, "sn") || !slices.Contains(options.Properties, "userCertificate") {
						t.Fatal(options, writes)
					}
					object := objectTestEntry(want)
					for attr, values := range request.Attributes {
						for _, value := range values {
							object.Attributes[strings.ToLower(attr)] = append(object.Attributes[strings.ToLower(attr)], value.Bytes())
						}
					}
					if mode == "wrong-readback" {
						object.Attributes["sn"] = [][]byte{[]byte("changed")}
					}
					if mode == "ranged-readback" {
						delete(object.Attributes, "description")
						object.Attributes["description;range=0-0"] = [][]byte{[]byte("one")}
						return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) {
							return []Object{object}, false, ErrIncompleteResult
						}, finish: func() error { return nil }}, nil
					}
					return objectTestCursor(object), nil
				}, func(_ context.Context, _ SearchOptions, controls []ldapWriteControl) (searchCursor, error) {
					if mode == "fallback-recycled" {
						if controls[0].oid == objectShowDeletedControl {
							return objectTestCursor(), nil
						}
						object := restorationDeletedEntry()
						object.Attributes["isrecycled"] = [][]byte{[]byte("TRUE")}
						return objectTestCursor(object), nil
					}
					if len(controls) != 1 || controls[0].oid != objectShowDeletedControl || !controls[0].critical {
						t.Fatal(controls)
					}
					object := restorationDeletedEntry()
					switch mode {
					case "explicit-missing-metadata":
						delete(object.Attributes, "lastknownparent")
						delete(object.Attributes, "msds-lastknownrdn")
					case "recycled", "tombstone-recycled-flag", "unknown-recycled-flag":
						object.Attributes["isrecycled"] = [][]byte{[]byte("TRUE")}
					case "protected":
						object.Attributes["systemflags"] = [][]byte{[]byte("-2147483648")}
					case "nc-root":
						object.Attributes["instancetype"] = [][]byte{[]byte("5")}
					case "schema":
						object.Attributes["objectclass"] = [][]byte{[]byte("attributeSchema")}
					}
					return objectTestCursor(object), nil
				}, func(_ context.Context, write ldapWriteRequest) ldapWriteAttempt {
					writes++
					if len(write.modifications) != 5 || write.modifications[0].attribute != "isDeleted" || write.modifications[1].attribute != "distinguishedName" || string(write.modifications[1].values[0]) != want || write.dn != objectGUIDTarget(objectTestGUID()) {
						t.Fatal(write)
					}
					for _, mod := range write.modifications[2:] {
						if mod.operation != 2 {
							t.Fatal(mod)
						}
						if mod.attribute == "userCertificate" && !bytes.Equal(mod.values[0], []byte{0, 255, 128}) {
							t.Fatal(mod)
						}
					}
					if mode == "missing-mandatory" {
						return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 65, Diagnostic: "another mandatory class attribute missing"}}
					}
					return ldapWriteAttempt{State: ldapWriteAccepted}
				})
				result, err := client.RestoreObject(context.Background(), request)
				if result.Mode != RestoreLegacyTombstone {
					t.Fatal(result.Mode)
				}
				switch mode {
				case "recycled", "fallback-recycled", "protected", "nc-root", "schema", "naming-conflict":
					if err == nil || writes != 0 || result.Mutation.State != ObjectWriteNotAttempted {
						t.Fatal(result, err, writes)
					}
				case "missing-mandatory":
					if err == nil || writes != 1 || result.Mutation.State != ObjectWriteRejected {
						t.Fatal(result, err, writes)
					}
				case "wrong-readback", "ranged-readback":
					if err == nil || writes != 1 || result.Mutation.State != ObjectWriteAccepted || result.Mutation.Verified {
						t.Fatal(result, err, writes)
					}
				default:
					if err != nil || writes != 1 || !result.Mutation.Verified || result.Mutation.State != ObjectWriteAccepted {
						t.Fatal(result, err, writes)
					}
				}
				if mode == "unknown" || mode == "feature-denied" {
					if result.Capabilities.RecycleBinEnabled != nil || result.Capabilities.Error == nil || result.Deleted.State != DeletedStateUnknown {
						t.Fatal(result)
					}
				}
				if (mode == "disabled" || mode == "tombstone-recycled-flag") && result.Deleted.State != DeletedStateTombstone {
					t.Fatal(result.Deleted)
				}
				if mode == "unknown-recycled-flag" && (result.Capabilities.RecycleBinEnabled != nil || result.Capabilities.Error == nil || result.Deleted.State != DeletedStateTombstone) {
					t.Fatal(result)
				}
			})
		}
	}
}

func TestRestoreAttributesRejectReservedAndInvalidValuesBeforeDispatch(t *testing.T) {
	for _, attribute := range []string{"objectGUID", "distinguishedName", "objectClass", "name", "ISDELETED", "isRecycled", "lastKnownParent", "msDS-LastKnownRDN", "systemFlags", "instanceType", "bad;range=0-*"} {
		var client *Client
		_, err := client.RestoreObject(context.Background(), RestoreObjectRequest{Identity: objectTestIdentity(), Mode: RestoreLegacyTombstone, Attributes: map[string][]RawValue{attribute: {NewRawValue([]byte("value"))}}})
		if !errors.Is(err, ErrInvalidObjectRestore) || errors.Is(err, ErrClosed) {
			t.Fatal(attribute, err)
		}
	}
	for _, values := range [][]RawValue{nil, {NewRawValue([]byte("duplicate")), NewRawValue([]byte("duplicate"))}} {
		if _, err := restoreAttributeModifications(map[string][]RawValue{"sn": values}); !errors.Is(err, ErrInvalidObjectRestore) {
			t.Fatal(values, err)
		}
	}
	var client *Client
	if _, err := client.RestoreObject(context.Background(), RestoreObjectRequest{Identity: objectTestIdentity(), Attributes: map[string][]RawValue{"sn": {NewRawValue([]byte("value"))}}}); !errors.Is(err, ErrInvalidObjectRestore) {
		t.Fatal(err)
	}
	if _, err := client.RestoreObject(context.Background(), RestoreObjectRequest{Identity: objectTestIdentity(), Mode: 99}); !errors.Is(err, ErrInvalidObjectRestore) {
		t.Fatal(err)
	}
}

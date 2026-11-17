package acceptance

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_object_restoration "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/object_restoration"
)

func TestLegacyRestoreAtomicAttributesAndUnknownFeatureState(t *testing.T) {
	for _, kind := range []string{admodel.CapabilityActiveDirectory, admodel.CapabilityADLDS} {
		for _, mode := range []string{"unknown", "disabled", "enabled", "tombstone-recycled-flag", "unknown-recycled-flag", "feature-denied", "explicit-missing-metadata", "missing-mandatory", "wrong-readback", "ranged-readback", "recycled", "fallback-recycled", "protected", "nc-root", "schema", "naming-conflict"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				writes := 0
				identity, _ := admodel.IdentityByGUID(InternalObjectTestGUID().String())
				request := admodel.RestoreObjectRequest{
					Identity: identity,
					Mode:     admodel.RestoreLegacyTombstone,
					Attributes: map[string][]admodel.RawValue{
						"sn": {
							admodel.NewRawValue([]byte("Required")),
						},
						"description": {
							admodel.NewRawValue([]byte("one")),
							admodel.NewRawValue([]byte("two")),
						},
						"userCertificate": {admodel.NewRawValue([]byte{0, 255, 128})},
					},
				}
				want := `cn=Jörg\, 李,OU=People,DC=example`
				if mode == "explicit-missing-metadata" {
					name := "Explicit"
					request.NewName = &name
					request.TargetParent, _ = admodel.IdentityByDN("OU=People,DC=example")
					want = "cn=Explicit,OU=People,DC=example"
				}
				if mode == "naming-conflict" {
					request.Attributes["CN"] = []admodel.RawValue{
						admodel.NewRawValue([]byte("different")),
					}
				}
				client := InternalRestorationTestClient(
					t,
					kind,
					func(_ context.Context, options admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
						featureMode := "feature-hidden"
						if mode == "disabled" || mode == "tombstone-recycled-flag" {
							featureMode = "feature-disabled"
						}
						if mode == "enabled" || mode == "recycled" {
							featureMode = ""
						}
						if mode == "feature-denied" && options.Base == InternalRestorationDSA {
							return nil, &admodel.LDAPError{Code: 50}
						}
						if cursor, ok := InternalRestorationFeatureCursor(
							options,
							featureMode,
						); ok {
							return cursor, nil
						}
						if options.Base == "OU=People,DC=example" {
							return InternalObjectTestCursor(
								InternalObjectTestEntry(options.Base),
							), nil
						}
						if writes != 1 || !slices.Contains(options.Properties, "sn") ||
							!slices.Contains(options.Properties, "userCertificate") {
							t.Fatal(options, writes)
						}
						object := InternalObjectTestEntry(want)
						for attr, values := range request.Attributes {
							for _, value := range values {
								object.Attributes[strings.ToLower(attr)] = append(
									object.Attributes[strings.ToLower(attr)],
									value.Bytes(),
								)
							}
						}
						if mode == "wrong-readback" {
							object.Attributes["sn"] = [][]byte{[]byte("changed")}
						}
						if mode == "ranged-readback" {
							delete(object.Attributes, "description")
							object.Attributes["description;range=0-0"] = [][]byte{[]byte("one")}
							return InternalTestSearchCursor{
								InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
									return []admodel.Object{
										object,
									}, false, admodel.ErrIncompleteResult
								},
								InternalFinish: func() error { return nil },
							}, nil
						}
						return InternalObjectTestCursor(object), nil
					},
					func(_ context.Context, _ admodel.SearchOptions, controls []admodel.InternalLdapWriteControl) (admodel.InternalSearchCursor, error) {
						if mode == "fallback-recycled" {
							if controls[0].InternalOid == admodel.InternalObjectShowDeletedControl {
								return InternalObjectTestCursor(), nil
							}
							object := InternalRestorationDeletedEntry()
							object.Attributes["isrecycled"] = [][]byte{[]byte("TRUE")}
							return InternalObjectTestCursor(object), nil
						}
						if len(controls) != 1 ||
							controls[0].InternalOid != admodel.InternalObjectShowDeletedControl ||
							!controls[0].InternalCritical {
							t.Fatal(controls)
						}
						object := InternalRestorationDeletedEntry()
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
						return InternalObjectTestCursor(object), nil
					},
					func(_ context.Context, write admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
						writes++
						if len(write.InternalModifications) != 5 ||
							write.InternalModifications[0].InternalAttribute != "isDeleted" ||
							write.InternalModifications[1].InternalAttribute != "distinguishedName" ||
							string(write.InternalModifications[1].InternalValues[0]) != want ||
							write.InternalDn != admodel.InternalObjectGUIDTarget(
								InternalObjectTestGUID(),
							) {
							t.Fatal(write)
						}
						for _, mod := range write.InternalModifications[2:] {
							if mod.InternalOperation != 2 {
								t.Fatal(mod)
							}
							if mod.InternalAttribute == "userCertificate" &&
								!bytes.Equal(mod.InternalValues[0], []byte{0, 255, 128}) {
								t.Fatal(mod)
							}
						}
						if mode == "missing-mandatory" {
							return admodel.InternalLdapWriteAttempt{
								State: admodel.InternalLdapWriteRejected,
								Err: &admodel.LDAPError{
									Code:       65,
									Diagnostic: "another mandatory class attribute missing",
								},
							}
						}
						return admodel.InternalLdapWriteAttempt{
							State: admodel.InternalLdapWriteAccepted,
						}
					},
				)
				result, err := adservice_object_restoration.New(client).
					RestoreObject(context.Background(), request)
				if result.Mode != admodel.RestoreLegacyTombstone {
					t.Fatal(result.Mode)
				}
				switch mode {
				case "recycled",
					"fallback-recycled",
					"protected",
					"nc-root",
					"schema",
					"naming-conflict":
					if err == nil || writes != 0 ||
						result.Mutation.State != admodel.ObjectWriteNotAttempted {
						t.Fatal(result, err, writes)
					}
				case "missing-mandatory":
					if err == nil || writes != 1 ||
						result.Mutation.State != admodel.ObjectWriteRejected {
						t.Fatal(result, err, writes)
					}
				case "wrong-readback", "ranged-readback":
					if err == nil || writes != 1 ||
						result.Mutation.State != admodel.ObjectWriteAccepted ||
						result.Mutation.Verified {
						t.Fatal(result, err, writes)
					}
				default:
					if err != nil || writes != 1 || !result.Mutation.Verified ||
						result.Mutation.State != admodel.ObjectWriteAccepted {
						t.Fatal(result, err, writes)
					}
				}
				if mode == "unknown" || mode == "feature-denied" {
					if result.Capabilities.RecycleBinEnabled != nil ||
						result.Capabilities.Error == nil ||
						result.Deleted.State != admodel.DeletedStateUnknown {
						t.Fatal(result)
					}
				}
				if (mode == "disabled" || mode == "tombstone-recycled-flag") &&
					result.Deleted.State != admodel.DeletedStateTombstone {
					t.Fatal(result.Deleted)
				}
				if mode == "unknown-recycled-flag" &&
					(result.Capabilities.RecycleBinEnabled != nil || result.Capabilities.Error == nil || result.Deleted.State != admodel.DeletedStateTombstone) {
					t.Fatal(result)
				}
			})
		}
	}
}

func TestRestoreAttributesRejectReservedAndInvalidValuesBeforeDispatch(t *testing.T) {
	for _, attribute := range []string{"objectGUID", "distinguishedName", "objectClass", "name", "ISDELETED", "isRecycled", "lastKnownParent", "msDS-LastKnownRDN", "systemFlags", "instanceType", "bad;range=0-*"} {
		var client *adengine.Client
		_, err := adservice_object_restoration.New(client).
			RestoreObject(context.Background(), admodel.RestoreObjectRequest{Identity: InternalObjectTestIdentity(), Mode: admodel.RestoreLegacyTombstone, Attributes: map[string][]admodel.RawValue{attribute: {admodel.NewRawValue([]byte("value"))}}})
		if !errors.Is(err, admodel.ErrInvalidObjectRestore) || errors.Is(err, admodel.ErrClosed) {
			t.Fatal(attribute, err)
		}
	}
	for _, values := range [][]admodel.RawValue{nil, {admodel.NewRawValue([]byte("duplicate")), admodel.NewRawValue([]byte("duplicate"))}} {
		if _, err := admodel.InternalRestoreAttributeModifications(
			map[string][]admodel.RawValue{"sn": values},
		); !errors.Is(
			err,
			admodel.ErrInvalidObjectRestore,
		) {
			t.Fatal(values, err)
		}
	}
	var client *adengine.Client
	if _, err := adservice_object_restoration.New(client).
		RestoreObject(context.Background(), admodel.RestoreObjectRequest{Identity: InternalObjectTestIdentity(), Attributes: map[string][]admodel.RawValue{"sn": {admodel.NewRawValue([]byte("value"))}}}); !errors.Is(
		err,
		admodel.ErrInvalidObjectRestore,
	) {
		t.Fatal(err)
	}
	if _, err := adservice_object_restoration.New(client).
		RestoreObject(context.Background(), admodel.RestoreObjectRequest{Identity: InternalObjectTestIdentity(), Mode: 99}); !errors.Is(
		err,
		admodel.ErrInvalidObjectRestore,
	) {
		t.Fatal(err)
	}
}

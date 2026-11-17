//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_object_restoration "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/object_restoration"
)

func TestNativeRestoreObjectModifyAndControls(t *testing.T) {
	for _, code := range []byte{0, 50, 68} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			target := `cn=Jörg\, 李,OU=People,DC=example`
			mods := InternalSearchBER(
				0x30,
				InternalSearchBER(
					0x30,
					[]byte{10, 1, 1},
					InternalSearchBER(
						0x30,
						InternalSearchBER(4, []byte("isDeleted")),
						InternalSearchBER(0x31),
					),
				),
				InternalSearchBER(
					0x30,
					[]byte{10, 1, 2},
					InternalSearchBER(
						0x30,
						InternalSearchBER(4, []byte("distinguishedName")),
						InternalSearchBER(0x31, InternalSearchBER(4, []byte(target))),
					),
				),
			)
			body := append(
				InternalSearchBER(
					4,
					[]byte(admodel.InternalObjectGUIDTarget(InternalObjectTestGUID())),
				),
				mods...)
			controls := InternalSearchBER(
				0xa0,
				InternalSearchBER(
					0x30,
					InternalSearchBER(4, []byte(admodel.InternalObjectShowDeletedControl)),
					[]byte{1, 1, 255},
					InternalSearchBER(4),
				),
			)
			fixture := InternalNewWriteWireFixture(t, 0x66, 0x67, body, controls, code)
			var owners InternalSearchNativeCounts
			client := InternalSearchWireClient(
				t,
				&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
				InternalCountedSearchAPI(&owners),
			)
			native := adengine.InternalClientSession(client).(*adengine.InternalLdapSession)
			writes, readbacks := 0, 0
			fake := InternalRestorationTestClient(
				t,
				admodel.CapabilityActiveDirectory,
				func(_ context.Context, options admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					if cursor, ok := InternalRestorationFeatureCursor(options, ""); ok {
						return cursor, nil
					}
					if options.Base == "OU=People,DC=example" {
						return InternalObjectTestCursor(InternalObjectTestEntry(options.Base)), nil
					}
					readbacks++
					return InternalObjectTestCursor(InternalObjectTestEntry(target)), nil
				},
				func(context.Context, admodel.SearchOptions, []admodel.InternalLdapWriteControl) (admodel.InternalSearchCursor, error) {
					return InternalObjectTestCursor(InternalRestorationDeletedEntry()), nil
				},
				func(ctx context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					writes++
					return native.InternalLdapWrite(ctx, request)
				},
			)
			session := adengine.InternalClientSession(fake).(InternalRestorationTestSession)
			session.InternalFinish = native.InternalClose
			(*adengine.InternalClientSessionPointer(client)) = session
			identity, _ := admodel.IdentityByGUID(InternalObjectTestGUID().String())
			result, err := adservice_object_restoration.New(client).
				RestoreObject(context.Background(), admodel.RestoreObjectRequest{Identity: identity})
			if code == 0 {
				if err != nil || !result.Mutation.Verified ||
					result.Mutation.State != admodel.ObjectWriteAccepted ||
					readbacks != 1 {
					t.Fatal(result, err, readbacks)
				}
			} else {
				var ldapErr *admodel.LDAPError
				if !errors.As(err, &ldapErr) || ldapErr.Code != uint32(code) ||
					result.Mutation.State != admodel.ObjectWriteRejected ||
					readbacks != 0 {
					t.Fatal(result, err, readbacks)
				}
			}
			if writes != 1 {
				t.Fatal(writes)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if owners != (InternalSearchNativeCounts{}) {
				t.Fatal(owners)
			}
		})
	}
}

func TestNativeLegacyRestoreAtomicAttributeBytes(t *testing.T) {
	for _, code := range []byte{0, 65} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			target := `cn=Jörg\, 李,OU=People,DC=example`
			mod := func(attribute string, operation byte, values ...[]byte) []byte {
				var encoded [][]byte
				for _, value := range values {
					encoded = append(encoded, InternalSearchBER(4, value))
				}
				return InternalSearchBER(
					0x30,
					[]byte{10, 1, operation},
					InternalSearchBER(
						0x30,
						InternalSearchBER(4, []byte(attribute)),
						InternalSearchBER(0x31, encoded...),
					),
				)
			}
			mods := InternalSearchBER(
				0x30,
				mod("isDeleted", 1),
				mod("distinguishedName", 2, []byte(target)),
				mod("description", 2, []byte("one"), []byte("two")),
				mod("sn", 2, []byte("Required 李")),
				mod("userCertificate", 2, []byte{0, 255, 128}),
			)
			body := append(
				InternalSearchBER(
					4,
					[]byte(admodel.InternalObjectGUIDTarget(InternalObjectTestGUID())),
				),
				mods...)
			controls := InternalSearchBER(
				0xa0,
				InternalSearchBER(
					0x30,
					InternalSearchBER(4, []byte(admodel.InternalObjectShowDeletedControl)),
					[]byte{1, 1, 255},
					InternalSearchBER(4),
				),
			)
			fixture := InternalNewWriteWireFixture(t, 0x66, 0x67, body, controls, code)
			var owners InternalSearchNativeCounts
			client := InternalSearchWireClient(
				t,
				&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
				InternalCountedSearchAPI(&owners),
			)
			native := adengine.InternalClientSession(client).(*adengine.InternalLdapSession)
			request := admodel.RestoreObjectRequest{
				Identity: admodel.InternalObjectGUIDIdentity(InternalObjectTestGUID()),
				Mode:     admodel.RestoreLegacyTombstone,
				Attributes: map[string][]admodel.RawValue{
					"description": {
						admodel.NewRawValue([]byte("one")),
						admodel.NewRawValue([]byte("two")),
					},
					"sn":              {admodel.NewRawValue([]byte("Required 李"))},
					"userCertificate": {admodel.NewRawValue([]byte{0, 255, 128})},
				},
			}
			writes := 0
			fake := InternalRestorationTestClient(
				t,
				admodel.CapabilityADLDS,
				func(_ context.Context, options admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					if cursor, ok := InternalRestorationFeatureCursor(
						options,
						"feature-hidden",
					); ok {
						return cursor, nil
					}
					if options.Base == "OU=People,DC=example" {
						return InternalObjectTestCursor(InternalObjectTestEntry(options.Base)), nil
					}
					object := InternalObjectTestEntry(target)
					for attribute, values := range request.Attributes {
						for _, value := range values {
							object.Attributes[strings.ToLower(attribute)] = append(
								object.Attributes[strings.ToLower(attribute)],
								value.Bytes(),
							)
						}
					}
					return InternalObjectTestCursor(object), nil
				},
				func(_ context.Context, _ admodel.SearchOptions, controls []admodel.InternalLdapWriteControl) (admodel.InternalSearchCursor, error) {
					if len(controls) != 1 ||
						controls[0].InternalOid != admodel.InternalObjectShowDeletedControl ||
						!controls[0].InternalCritical {
						t.Fatal(controls)
					}
					object := InternalRestorationDeletedEntry()
					object.Attributes["isrecycled"] = [][]byte{[]byte("TRUE")}
					return InternalObjectTestCursor(object), nil
				},
				func(ctx context.Context, write admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					writes++
					return native.InternalLdapWrite(ctx, write)
				},
			)
			session := adengine.InternalClientSession(fake).(InternalRestorationTestSession)
			session.InternalFinish = native.InternalClose
			(*adengine.InternalClientSessionPointer(client)) = session
			result, err := adservice_object_restoration.New(client).
				RestoreObject(context.Background(), request)
			if code == 0 {
				if err != nil || !result.Mutation.Verified ||
					result.Mutation.State != admodel.ObjectWriteAccepted {
					t.Fatal(result, err)
				}
			} else {
				var ldapErr *admodel.LDAPError
				if !errors.As(err, &ldapErr) || ldapErr.Code != 65 ||
					result.Mutation.State != admodel.ObjectWriteRejected {
					t.Fatal(result, err)
				}
			}
			if writes != 1 || result.Capabilities.RecycleBinEnabled != nil ||
				result.Capabilities.Error == nil {
				t.Fatal(writes, result.Capabilities)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if owners != (InternalSearchNativeCounts{}) {
				t.Fatal(owners)
			}
		})
	}
}

func TestNativeDeletedObjectsPagedControlsAndCleanup(t *testing.T) {
	for _, mode := range []string{"complete", "limit", "denied", "ranged", "recycled", "tombstone"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() { done <- InternalServeRestorationSearch(listener, mode) }()
			var owners InternalSearchNativeCounts
			client := InternalSearchWireClient(
				t,
				&InternalSearchWireFixture{InternalListener: listener},
				InternalCountedSearchAPI(&owners),
			)
			native := adengine.InternalClientSession(client).(*adengine.InternalLdapSession)
			fake := InternalRestorationTestClient(
				t,
				admodel.CapabilityActiveDirectory,
				func(_ context.Context, options admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					featureMode := ""
					if mode == "tombstone" {
						featureMode = "feature-hidden"
					}
					cursor, ok := InternalRestorationFeatureCursor(options, featureMode)
					if !ok {
						t.Fatal(options)
					}
					return cursor, nil
				},
				native.InternalStartSearchControls,
				func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					t.Fatal("read-only discovery wrote")
					return admodel.InternalLdapWriteAttempt{}
				},
			)
			session := adengine.InternalClientSession(fake).(InternalRestorationTestSession)
			session.InternalFinish = native.InternalClose
			(*adengine.InternalClientSessionPointer(client)) = session
			query := admodel.DeletedObjectQuery{
				Search: admodel.SearchOptions{
					Scope:    admodel.ScopeSubtree,
					PageSize: 1,
				},
				IncludeRecycled:         mode == "recycled",
				IncludeDeactivatedLinks: true,
			}
			if mode == "limit" {
				query.Search.ResultLimit = 1
			}
			result, err := adservice_object_restoration.New(client).
				DeletedObjects(context.Background(), query)
			if len(result.Objects) == 0 {
				t.Fatal(result, err)
			}
			switch mode {
			case "complete", "recycled":
				if err != nil || !result.Complete || len(result.Objects) != 2 {
					t.Fatal(result, err)
				}
			case "limit":
				if err != nil || result.Complete || !result.Observation.LimitReached ||
					len(result.Objects) != 1 {
					t.Fatal(result, err)
				}
			case "tombstone":
				if err == nil || result.Complete || len(result.Objects) != 2 ||
					result.Objects[0].State != admodel.DeletedStateTombstone ||
					result.Capabilities.RecycleBinEnabled != nil {
					t.Fatal(result, err)
				}
			default:
				if err == nil || result.Complete || len(result.Objects) != 1 {
					t.Fatal(result, err)
				}
			}
			if mode == "recycled" && result.Objects[0].State != admodel.DeletedStateRecycled {
				t.Fatal(result.Objects)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("wire fixture did not finish")
			}
			if owners != (InternalSearchNativeCounts{}) {
				t.Fatal(owners)
			}
		})
	}
}

func InternalServeRestorationSearch(listener net.Listener, mode string) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	pages, cleanup := 0, 0
	for {
		packet, err := InternalReadSearchBER(conn)
		if err != nil {
			return err
		}
		id, rest, err := InternalTakeSearchBER(packet, 2)
		if err != nil || len(rest) == 0 {
			return admodel.ErrInvalidResult
		}
		if rest[0] == 0x42 {
			want := 2
			if mode == "limit" || mode == "denied" || mode == "ranged" {
				want = 1
			}
			if pages != want || (mode == "limit" && cleanup != 1) {
				return fmt.Errorf("pages=%d cleanup=%d", pages, cleanup)
			}
			return nil
		}
		request, controls, err := InternalTakeSearchBER(rest, 0x63)
		if err != nil {
			return err
		}
		if !strings.Contains(string(request), "isDeleted") ||
			!strings.Contains(string(request), "TRUE") {
			return errors.New("deleted-object filter was not encoded")
		}
		size, err := InternalSearchWirePageSize(controls)
		if err != nil {
			return err
		}
		items, _, err := InternalTakeSearchBER(controls, 0xa0)
		if err != nil {
			return err
		}
		_, items, err = InternalTakeSearchBER(items, 0x30)
		if err != nil {
			return err
		} // native paging control
		oid := admodel.InternalObjectShowDeletedControl
		if mode == "recycled" {
			oid = admodel.InternalObjectShowRecycledControl
		}
		for _, want := range []string{oid, admodel.InternalObjectShowDeactivatedLinksControl} {
			var item []byte
			item, items, err = InternalTakeSearchBER(items, 0x30)
			if err != nil {
				return err
			}
			name, tail, err := InternalTakeSearchBER(item, 4)
			if err != nil {
				return err
			}
			critical, tail, err := InternalTakeSearchBER(tail, 1)
			if err != nil {
				return err
			}
			value, tail, err := InternalTakeSearchBER(tail, 4)
			if err != nil || string(name) != want || len(critical) != 1 || critical[0] == 0 ||
				len(value) != 0 ||
				len(tail) != 0 {
				return fmt.Errorf("bad feature control %x", item)
			}
		}
		if len(items) != 0 {
			return errors.New("unexpected control")
		}
		cookie := []byte(nil)
		code := byte(0)
		if size == 0 {
			cleanup++
		} else {
			pages++
			if pages > 2 || size != 1 {
				return errors.New("unexpected page")
			}
			if pages == 1 {
				cookie = []byte("continue")
			}
			attrs := append(
				InternalSearchWireAttribute("objectGUID", InternalObjectTestGUID().Bytes()),
				InternalSearchWireAttribute("isDeleted", []byte("TRUE"))...)
			attrs = append(
				attrs,
				InternalSearchWireAttribute("lastKnownParent", []byte("OU=People,DC=example"))...)
			attrs = append(
				attrs,
				InternalSearchWireAttribute("msDS-LastKnownRDN", []byte("Jörg, 李"))...)
			if mode == "recycled" || mode == "tombstone" {
				attrs = append(attrs, InternalSearchWireAttribute("isRecycled", []byte("TRUE"))...)
			}
			if mode == "ranged" {
				attrs = append(
					attrs,
					InternalSearchWireAttribute(
						"member;range=0-0",
						[]byte("CN=first,DC=example"),
					)...)
			}
			entry := InternalSearchBER(
				0x64,
				InternalSearchBER(4, []byte(InternalRestorationDeletedDN)),
				InternalSearchBER(0x30, attrs),
			)
			if _, err := conn.Write(
				InternalSearchBER(0x30, InternalSearchBER(2, id), entry),
			); err != nil {
				return err
			}
			if mode == "denied" {
				code = 50
			}
		}
		pageControl := InternalSearchBER(
			0xa0,
			InternalSearchBER(
				0x30,
				InternalSearchBER(4, []byte("1.2.840.113556.1.4.319")),
				InternalSearchBER(
					4,
					InternalSearchBER(0x30, []byte{2, 1, 0}, InternalSearchBER(4, cookie)),
				),
			),
		)
		if _, err := conn.Write(
			InternalSearchBER(
				0x30,
				InternalSearchBER(2, id),
				InternalSearchBER(0x65, []byte{10, 1, code, 4, 0, 4, 0}),
				pageControl,
			),
		); err != nil {
			return err
		}
	}
}

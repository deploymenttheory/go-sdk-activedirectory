//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNativeRestoreObjectModifyAndControls(t *testing.T) {
	for _, code := range []byte{0, 50, 68} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			target := `cn=Jörg\, 李,OU=People,DC=example`
			mods := searchBER(0x30,
				searchBER(0x30, []byte{10, 1, 1}, searchBER(0x30, searchBER(4, []byte("isDeleted")), searchBER(0x31))),
				searchBER(0x30, []byte{10, 1, 2}, searchBER(0x30, searchBER(4, []byte("distinguishedName")), searchBER(0x31, searchBER(4, []byte(target))))))
			body := append(searchBER(4, []byte(objectGUIDTarget(objectTestGUID()))), mods...)
			controls := searchBER(0xa0, searchBER(0x30, searchBER(4, []byte(objectShowDeletedControl)), []byte{1, 1, 255}, searchBER(4)))
			fixture := newWriteWireFixture(t, 0x66, 0x67, body, controls, code)
			var owners searchNativeCounts
			client := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&owners))
			native := client.session.(*ldapSession)
			writes, readbacks := 0, 0
			fake := restorationTestClient(t, CapabilityActiveDirectory, func(_ context.Context, options SearchOptions) (searchCursor, error) {
				if cursor, ok := restorationFeatureCursor(options, ""); ok {
					return cursor, nil
				}
				if options.Base == "OU=People,DC=example" {
					return objectTestCursor(objectTestEntry(options.Base)), nil
				}
				readbacks++
				return objectTestCursor(objectTestEntry(target)), nil
			}, func(context.Context, SearchOptions, []ldapWriteControl) (searchCursor, error) {
				return objectTestCursor(restorationDeletedEntry()), nil
			}, func(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
				writes++
				return native.ldapWrite(ctx, request)
			})
			session := fake.session.(restorationTestSession)
			session.finish = native.close
			client.session = session
			identity, _ := IdentityByGUID(objectTestGUID().String())
			result, err := client.RestoreObject(context.Background(), RestoreObjectRequest{Identity: identity})
			if code == 0 {
				if err != nil || !result.Mutation.Verified || result.Mutation.State != ObjectWriteAccepted || readbacks != 1 {
					t.Fatal(result, err, readbacks)
				}
			} else {
				var ldapErr *LDAPError
				if !errors.As(err, &ldapErr) || ldapErr.Code != uint32(code) || result.Mutation.State != ObjectWriteRejected || readbacks != 0 {
					t.Fatal(result, err, readbacks)
				}
			}
			if writes != 1 {
				t.Fatal(writes)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if owners != (searchNativeCounts{}) {
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
					encoded = append(encoded, searchBER(4, value))
				}
				return searchBER(0x30, []byte{10, 1, operation}, searchBER(0x30, searchBER(4, []byte(attribute)), searchBER(0x31, encoded...)))
			}
			mods := searchBER(0x30, mod("isDeleted", 1), mod("distinguishedName", 2, []byte(target)), mod("description", 2, []byte("one"), []byte("two")), mod("sn", 2, []byte("Required 李")), mod("userCertificate", 2, []byte{0, 255, 128}))
			body := append(searchBER(4, []byte(objectGUIDTarget(objectTestGUID()))), mods...)
			controls := searchBER(0xa0, searchBER(0x30, searchBER(4, []byte(objectShowDeletedControl)), []byte{1, 1, 255}, searchBER(4)))
			fixture := newWriteWireFixture(t, 0x66, 0x67, body, controls, code)
			var owners searchNativeCounts
			client := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&owners))
			native := client.session.(*ldapSession)
			request := RestoreObjectRequest{Identity: objectGUIDIdentity(objectTestGUID()), Mode: RestoreLegacyTombstone, Attributes: map[string][]RawValue{
				"description": {NewRawValue([]byte("one")), NewRawValue([]byte("two"))}, "sn": {NewRawValue([]byte("Required 李"))}, "userCertificate": {NewRawValue([]byte{0, 255, 128})},
			}}
			writes := 0
			fake := restorationTestClient(t, CapabilityADLDS, func(_ context.Context, options SearchOptions) (searchCursor, error) {
				if cursor, ok := restorationFeatureCursor(options, "feature-hidden"); ok {
					return cursor, nil
				}
				if options.Base == "OU=People,DC=example" {
					return objectTestCursor(objectTestEntry(options.Base)), nil
				}
				object := objectTestEntry(target)
				for attribute, values := range request.Attributes {
					for _, value := range values {
						object.Attributes[strings.ToLower(attribute)] = append(object.Attributes[strings.ToLower(attribute)], value.Bytes())
					}
				}
				return objectTestCursor(object), nil
			}, func(_ context.Context, _ SearchOptions, controls []ldapWriteControl) (searchCursor, error) {
				if len(controls) != 1 || controls[0].oid != objectShowDeletedControl || !controls[0].critical {
					t.Fatal(controls)
				}
				object := restorationDeletedEntry()
				object.Attributes["isrecycled"] = [][]byte{[]byte("TRUE")}
				return objectTestCursor(object), nil
			}, func(ctx context.Context, write ldapWriteRequest) ldapWriteAttempt {
				writes++
				return native.ldapWrite(ctx, write)
			})
			session := fake.session.(restorationTestSession)
			session.finish = native.close
			client.session = session
			result, err := client.RestoreObject(context.Background(), request)
			if code == 0 {
				if err != nil || !result.Mutation.Verified || result.Mutation.State != ObjectWriteAccepted {
					t.Fatal(result, err)
				}
			} else {
				var ldapErr *LDAPError
				if !errors.As(err, &ldapErr) || ldapErr.Code != 65 || result.Mutation.State != ObjectWriteRejected {
					t.Fatal(result, err)
				}
			}
			if writes != 1 || result.Capabilities.RecycleBinEnabled != nil || result.Capabilities.Error == nil {
				t.Fatal(writes, result.Capabilities)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if owners != (searchNativeCounts{}) {
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
			go func() { done <- serveRestorationSearch(listener, mode) }()
			var owners searchNativeCounts
			client := searchWireClient(t, &searchWireFixture{listener: listener}, countedSearchAPI(&owners))
			native := client.session.(*ldapSession)
			fake := restorationTestClient(t, CapabilityActiveDirectory, func(_ context.Context, options SearchOptions) (searchCursor, error) {
				featureMode := ""
				if mode == "tombstone" {
					featureMode = "feature-hidden"
				}
				cursor, ok := restorationFeatureCursor(options, featureMode)
				if !ok {
					t.Fatal(options)
				}
				return cursor, nil
			}, native.startSearchControls, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
				t.Fatal("read-only discovery wrote")
				return ldapWriteAttempt{}
			})
			session := fake.session.(restorationTestSession)
			session.finish = native.close
			client.session = session
			query := DeletedObjectQuery{Search: SearchOptions{Scope: ScopeSubtree, PageSize: 1}, IncludeRecycled: mode == "recycled", IncludeDeactivatedLinks: true}
			if mode == "limit" {
				query.Search.ResultLimit = 1
			}
			result, err := client.DeletedObjects(context.Background(), query)
			if len(result.Objects) == 0 {
				t.Fatal(result, err)
			}
			switch mode {
			case "complete", "recycled":
				if err != nil || !result.Complete || len(result.Objects) != 2 {
					t.Fatal(result, err)
				}
			case "limit":
				if err != nil || result.Complete || !result.Observation.LimitReached || len(result.Objects) != 1 {
					t.Fatal(result, err)
				}
			case "tombstone":
				if err == nil || result.Complete || len(result.Objects) != 2 || result.Objects[0].State != DeletedStateTombstone || result.Capabilities.RecycleBinEnabled != nil {
					t.Fatal(result, err)
				}
			default:
				if err == nil || result.Complete || len(result.Objects) != 1 {
					t.Fatal(result, err)
				}
			}
			if mode == "recycled" && result.Objects[0].State != DeletedStateRecycled {
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
			if owners != (searchNativeCounts{}) {
				t.Fatal(owners)
			}
		})
	}
}

func serveRestorationSearch(listener net.Listener, mode string) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	pages, cleanup := 0, 0
	for {
		packet, err := readSearchBER(conn)
		if err != nil {
			return err
		}
		id, rest, err := takeSearchBER(packet, 2)
		if err != nil || len(rest) == 0 {
			return ErrInvalidResult
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
		request, controls, err := takeSearchBER(rest, 0x63)
		if err != nil {
			return err
		}
		if !strings.Contains(string(request), "isDeleted") || !strings.Contains(string(request), "TRUE") {
			return errors.New("deleted-object filter was not encoded")
		}
		size, err := searchWirePageSize(controls)
		if err != nil {
			return err
		}
		items, _, err := takeSearchBER(controls, 0xa0)
		if err != nil {
			return err
		}
		_, items, err = takeSearchBER(items, 0x30)
		if err != nil {
			return err
		} // native paging control
		oid := objectShowDeletedControl
		if mode == "recycled" {
			oid = objectShowRecycledControl
		}
		for _, want := range []string{oid, objectShowDeactivatedLinksControl} {
			var item []byte
			item, items, err = takeSearchBER(items, 0x30)
			if err != nil {
				return err
			}
			name, tail, err := takeSearchBER(item, 4)
			if err != nil {
				return err
			}
			critical, tail, err := takeSearchBER(tail, 1)
			if err != nil {
				return err
			}
			value, tail, err := takeSearchBER(tail, 4)
			if err != nil || string(name) != want || len(critical) != 1 || critical[0] == 0 || len(value) != 0 || len(tail) != 0 {
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
			attrs := append(searchWireAttribute("objectGUID", objectTestGUID().Bytes()), searchWireAttribute("isDeleted", []byte("TRUE"))...)
			attrs = append(attrs, searchWireAttribute("lastKnownParent", []byte("OU=People,DC=example"))...)
			attrs = append(attrs, searchWireAttribute("msDS-LastKnownRDN", []byte("Jörg, 李"))...)
			if mode == "recycled" || mode == "tombstone" {
				attrs = append(attrs, searchWireAttribute("isRecycled", []byte("TRUE"))...)
			}
			if mode == "ranged" {
				attrs = append(attrs, searchWireAttribute("member;range=0-0", []byte("CN=first,DC=example"))...)
			}
			entry := searchBER(0x64, searchBER(4, []byte(restorationDeletedDN)), searchBER(0x30, attrs))
			if _, err := conn.Write(searchBER(0x30, searchBER(2, id), entry)); err != nil {
				return err
			}
			if mode == "denied" {
				code = 50
			}
		}
		pageControl := searchBER(0xa0, searchBER(0x30, searchBER(4, []byte("1.2.840.113556.1.4.319")), searchBER(4, searchBER(0x30, []byte{2, 1, 0}, searchBER(4, cookie)))))
		if _, err := conn.Write(searchBER(0x30, searchBER(2, id), searchBER(0x65, []byte{10, 1, code, 4, 0, 4, 0}), pageControl)); err != nil {
			return err
		}
	}
}

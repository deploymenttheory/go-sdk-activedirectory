//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security"
)

type serviceAccountNativeTestSession struct {
	*serviceAccountTestSession
	native *ldapSession
	calls  int
}

func (s *serviceAccountNativeTestSession) ldapWrite(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
	s.calls++
	runtime.GC()
	attempt := s.native.ldapWrite(ctx, request)
	if attempt.State == ldapWriteAccepted && attempt.Err == nil {
		s.serviceAccountTestSession.ldapWrite(ctx, request)
	}
	return attempt
}
func (s *serviceAccountNativeTestSession) encodeDACL(raw []byte, aces [][]byte) ([]byte, error) {
	return s.native.encodeDACL(raw, aces)
}
func (s *serviceAccountNativeTestSession) newDirectoryDescriptor(sddl string) ([]byte, error) {
	return s.native.newDirectoryDescriptor(sddl)
}

func TestServiceAccountNativeWholeDescriptorAndOpaqueACEs(t *testing.T) {
	native := &ldapSession{}
	raw, err := native.newDirectoryDescriptor("O:BAG:SYD:PAI(D;;RP;;;WD)(A;;RPWP;;;BA)(XA;;RP;;;WD;(@User.department == \"finance\"))(A;ID;RP;;;SY)S:(AU;SA;RP;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := ParseSID("S-1-5-21-1-2-3-1100")
	next, err := replaceServiceAccountReaders(native, raw, []SID{sid})
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	if !security.IsValidSecurityDescriptor(security.PSECURITY_DESCRIPTOR(uintptr(unsafe.Pointer(unsafe.SliceData(next))))) {
		t.Fatal("invalid native descriptor")
	}
	runtime.KeepAlive(next)
	if !bytes.Equal(raw[:4], next[:4]) {
		t.Fatal("control changed")
	}
	for _, at := range []int{4, 8, 12} {
		a := binary.LittleEndian.Uint32(raw[at : at+4])
		b := binary.LittleEndian.Uint32(next[at : at+4])
		size := uint32(8 + 4*int(raw[a+1]))
		if at == 12 {
			size = uint32(binary.LittleEndian.Uint16(raw[a+2 : a+4]))
		}
		if !bytes.Equal(raw[a:a+size], next[b:b+size]) {
			t.Fatal("component lost", at)
		}
	}
	before, _ := decodeDirectoryDACL(raw)
	after, _ := decodeDirectoryDACL(next)
	if len(after.aces) != 5 || !bytes.Equal(before.aces[0], after.aces[0]) || !bytes.Equal(before.aces[2], after.aces[2]) || !bytes.Equal(before.aces[3], after.aces[4]) {
		t.Fatal("opaque/deny/inherited ACE changed")
	}
}
func TestNativeCreateOutboundServiceAccountWire(t *testing.T) {
	native := &ldapSession{}
	descriptor, err := native.newDirectoryDescriptor("O:SYG:SYD:")
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err = replaceServiceAccountReaders(native, descriptor, nil)
	if err != nil {
		t.Fatal(err)
	}
	attribute := func(name string, value []byte) []byte {
		return searchBER(0x30, searchBER(4, []byte(name)), searchBER(0x31, searchBER(4, value)))
	}
	body := append(searchBER(4, []byte("cn=svc,OU=target,DC=example")), searchBER(0x30, attribute("msds-groupmsamembership", descriptor), attribute("msds-managedpasswordinterval", []byte("30")), attribute("samaccountname", []byte("svc$")), attribute("useraccountcontrol", []byte("4096")), attribute("objectClass", []byte("msDS-GroupManagedServiceAccount")), attribute("cn", []byte("svc")))...)
	for _, code := range []byte{0, 50, 68} {
		t.Run(fmt.Sprintf("LDAP%d", code), func(t *testing.T) {
			fixture := newWriteWireFixture(t, 0x68, 0x69, body, nil, code)
			var counts searchNativeCounts
			wire := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&counts))
			client, s := newServiceAccountTestClient(t)
			bridge := &serviceAccountNativeTestSession{serviceAccountTestSession: s, native: wire.session.(*ldapSession)}
			client.session = bridge
			s.finish = bridge.native.close
			result, err := client.CreateServiceAccount(context.Background(), CreateServiceAccountRequest{Kind: ServiceAccountGroupManaged, Name: "svc", OutboundAuthenticationOnly: true})
			if bridge.calls != 1 {
				t.Fatal("replayed", bridge.calls)
			}
			if code == 0 {
				if err != nil || !result.Complete || !result.Creation.Verified {
					t.Fatal(result, err)
				}
			} else {
				var ldapErr *LDAPError
				if !errors.As(err, &ldapErr) || ldapErr.Code != uint32(code) || result.Creation.State != ObjectWriteRejected {
					t.Fatal(result, err)
				}
			}
			if err = client.Close(); err != nil {
				t.Fatal(err)
			}
			if counts != (searchNativeCounts{}) {
				t.Fatal("native owners", counts)
			}
		})
	}
}
func TestNativeServiceAccountReaderCASWireAndPermission(t *testing.T) {
	native := &ldapSession{}
	raw, err := native.newDirectoryDescriptor("O:BAG:SYD:(A;;RPWP;;;BA)S:(AU;SA;RP;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	next, err := replaceServiceAccountReaders(native, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	mod := func(operation byte, value []byte) []byte {
		return searchBER(0x30, []byte{10, 1, operation}, searchBER(0x30, searchBER(4, []byte("msDS-GroupMSAMembership")), searchBER(0x31, searchBER(4, value))))
	}
	body := append(searchBER(4, []byte("<GUID=33221100554477668899aabbccddeeff>")), searchBER(0x30, mod(1, raw), mod(0, next))...)
	for _, code := range []byte{0, 16, 50} {
		t.Run(fmt.Sprintf("LDAP%d", code), func(t *testing.T) {
			fixture := newWriteWireFixture(t, 0x66, 0x67, body, nil, code)
			var counts searchNativeCounts
			wire := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&counts))
			client, s := newServiceAccountTestClient(t)
			object := serviceAccountTestEntry(ServiceAccountGroupManaged)
			object.Attributes["msds-groupmsamembership"] = [][]byte{raw}
			s.objects[strings.ToLower(object.DistinguishedName)] = object
			bridge := &serviceAccountNativeTestSession{serviceAccountTestSession: s, native: wire.session.(*ldapSession)}
			client.session = bridge
			s.finish = bridge.native.close
			empty := []Identity{}
			result, err := client.UpdateServiceAccount(context.Background(), UpdateServiceAccountRequest{Identity: objectTestIdentity(), PasswordReaders: &empty})
			if bridge.calls != 1 {
				t.Fatal(bridge.calls)
			}
			if code == 0 {
				if err != nil || !result.Mutation.Verified || result.Account == nil || len(result.Account.PasswordReaders) != 0 {
					t.Fatal(result, err)
				}
			} else {
				var ldapErr *LDAPError
				if !errors.As(err, &ldapErr) || ldapErr.Code != uint32(code) || result.Mutation.State != ObjectWriteRejected {
					t.Fatal(result, err)
				}
			}
			if err = client.Close(); err != nil {
				t.Fatal(err)
			}
			if counts != (searchNativeCounts{}) {
				t.Fatal(counts)
			}
		})
	}
}
func TestNativeComputerServiceAccountAssociationWire(t *testing.T) {
	const dn = "CN=svc-東京,DC=example"
	body := append(searchBER(4, []byte("<GUID=33221100554477668899aabbccddeeff>")), searchBER(0x30, searchBER(0x30, []byte{10, 1, 0}, searchBER(0x30, searchBER(4, []byte("msDS-HostServiceAccount")), searchBER(0x31, searchBER(4, []byte(dn))))))...)
	controls := searchBER(0xa0, searchBER(0x30, searchBER(4, []byte("1.2.840.113556.1.4.1413")), []byte{1, 1, 255}, searchBER(4, nil)))
	for _, code := range []byte{0, 20, 50} {
		t.Run(fmt.Sprintf("LDAP%d", code), func(t *testing.T) {
			fixture := newWriteWireFixture(t, 0x66, 0x67, body, controls, code)
			var counts searchNativeCounts
			wire := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&counts))
			client, s := newServiceAccountTestClient(t)
			computer := computerTestEntry(4096)
			s.objects[strings.ToLower(computer.DistinguishedName)] = computer
			account := serviceAccountTestEntry(ServiceAccountStandalone)
			account.DistinguishedName = dn
			account.Attributes["objectguid"] = [][]byte{make([]byte, 16)}
			s.objects[strings.ToLower(dn)] = account
			bridge := &serviceAccountNativeTestSession{serviceAccountTestSession: s, native: wire.session.(*ldapSession)}
			client.session = bridge
			s.finish = bridge.native.close
			identity, _ := IdentityByDN(dn)
			result, err := client.AddComputerServiceAccounts(context.Background(), ComputerServiceAccountRequest{Computer: objectTestIdentity(), Accounts: []Identity{identity}, Permissive: true})
			if bridge.calls != 1 {
				t.Fatal(bridge.calls)
			}
			if code == 0 {
				if err != nil || !result.Mutation.Verified {
					t.Fatal(result, err)
				}
			} else {
				var ldapErr *LDAPError
				if !errors.As(err, &ldapErr) || ldapErr.Code != uint32(code) || result.Mutation.State != ObjectWriteRejected {
					t.Fatal(result, err)
				}
			}
			if err = client.Close(); err != nil {
				t.Fatal(err)
			}
			if counts != (searchNativeCounts{}) {
				t.Fatal(counts)
			}
		})
	}
}

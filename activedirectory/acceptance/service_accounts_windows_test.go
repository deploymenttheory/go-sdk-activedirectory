//go:build windows && (amd64 || arm64)

package acceptance

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
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_service_accounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/service_accounts"
)

type InternalServiceAccountNativeTestSession struct {
	*InternalServiceAccountTestSession
	InternalNative *adengine.InternalLdapSession
	InternalCalls  int
}

func (s *InternalServiceAccountNativeTestSession) InternalLdapWrite(
	ctx context.Context,
	request admodel.InternalLdapWriteRequest,
) admodel.InternalLdapWriteAttempt {
	s.InternalCalls++
	runtime.GC()
	attempt := s.InternalNative.InternalLdapWrite(ctx, request)
	if attempt.State == admodel.InternalLdapWriteAccepted && attempt.Err == nil {
		s.InternalServiceAccountTestSession.InternalLdapWrite(ctx, request)
	}
	return attempt
}

func (s *InternalServiceAccountNativeTestSession) InternalEncodeDACL(
	raw []byte,
	aces [][]byte,
) ([]byte, error) {
	return s.InternalNative.InternalEncodeDACL(raw, aces)
}

func (s *InternalServiceAccountNativeTestSession) InternalNewDirectoryDescriptor(
	sddl string,
) ([]byte, error) {
	return s.InternalNative.InternalNewDirectoryDescriptor(sddl)
}

func TestServiceAccountNativeWholeDescriptorAndOpaqueACEs(t *testing.T) {
	native := &adengine.InternalLdapSession{}
	raw, err := native.InternalNewDirectoryDescriptor(
		"O:BAG:SYD:PAI(D;;RP;;;WD)(A;;RPWP;;;BA)(XA;;RP;;;WD;(@User.department == \"finance\"))(A;ID;RP;;;SY)S:(AU;SA;RP;;;WD)",
	)
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := admodel.ParseSID("S-1-5-21-1-2-3-1100")
	next, err := admodel.InternalReplaceServiceAccountReaders(native, raw, []admodel.SID{sid})
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	if !security.IsValidSecurityDescriptor(
		security.PSECURITY_DESCRIPTOR(uintptr(unsafe.Pointer(unsafe.SliceData(next)))),
	) {
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
	before, _ := admodel.InternalDecodeDirectoryDACL(raw)
	after, _ := admodel.InternalDecodeDirectoryDACL(next)
	if len(after.InternalAces) != 5 ||
		!bytes.Equal(before.InternalAces[0], after.InternalAces[0]) ||
		!bytes.Equal(before.InternalAces[2], after.InternalAces[2]) ||
		!bytes.Equal(before.InternalAces[3], after.InternalAces[4]) {
		t.Fatal("opaque/deny/inherited ACE changed")
	}
}

func TestNativeCreateOutboundServiceAccountWire(t *testing.T) {
	native := &adengine.InternalLdapSession{}
	descriptor, err := native.InternalNewDirectoryDescriptor("O:SYG:SYD:")
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err = admodel.InternalReplaceServiceAccountReaders(native, descriptor, nil)
	if err != nil {
		t.Fatal(err)
	}
	attribute := func(name string, value []byte) []byte {
		return InternalSearchBER(
			0x30,
			InternalSearchBER(4, []byte(name)),
			InternalSearchBER(0x31, InternalSearchBER(4, value)),
		)
	}
	body := append(
		InternalSearchBER(4, []byte("cn=svc,OU=target,DC=example")),
		InternalSearchBER(
			0x30,
			attribute("msds-groupmsamembership", descriptor),
			attribute("msds-managedpasswordinterval", []byte("30")),
			attribute("samaccountname", []byte("svc$")),
			attribute("useraccountcontrol", []byte("4096")),
			attribute("objectClass", []byte("msDS-GroupManagedServiceAccount")),
			attribute("cn", []byte("svc")),
		)...)
	for _, code := range []byte{0, 50, 68} {
		t.Run(fmt.Sprintf("LDAP%d", code), func(t *testing.T) {
			fixture := InternalNewWriteWireFixture(t, 0x68, 0x69, body, nil, code)
			var counts InternalSearchNativeCounts
			wire := InternalSearchWireClient(
				t,
				&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
				InternalCountedSearchAPI(&counts),
			)
			client, s := InternalNewServiceAccountTestClient(t)
			bridge := &InternalServiceAccountNativeTestSession{
				InternalServiceAccountTestSession: s,
				InternalNative:                    (*adengine.InternalClientSessionPointer(wire)).(*adengine.InternalLdapSession),
			}
			(*adengine.InternalClientSessionPointer(client)) = bridge
			s.InternalFinish = bridge.InternalNative.InternalClose
			result, err := adservice_service_accounts.New(client).
				CreateServiceAccount(context.Background(), admodel.CreateServiceAccountRequest{Kind: admodel.ServiceAccountGroupManaged, Name: "svc", OutboundAuthenticationOnly: true})
			if bridge.InternalCalls != 1 {
				t.Fatal("replayed", bridge.InternalCalls)
			}
			if code == 0 {
				if err != nil || !result.Complete || !result.Creation.Verified {
					t.Fatal(result, err)
				}
			} else {
				var ldapErr *admodel.LDAPError
				if !errors.As(err, &ldapErr) || ldapErr.Code != uint32(code) ||
					result.Creation.State != admodel.ObjectWriteRejected {
					t.Fatal(result, err)
				}
			}
			if err = client.Close(); err != nil {
				t.Fatal(err)
			}
			if counts != (InternalSearchNativeCounts{}) {
				t.Fatal("native owners", counts)
			}
		})
	}
}

func TestNativeServiceAccountReaderCASWireAndPermission(t *testing.T) {
	native := &adengine.InternalLdapSession{}
	raw, err := native.InternalNewDirectoryDescriptor("O:BAG:SYD:(A;;RPWP;;;BA)S:(AU;SA;RP;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	next, err := admodel.InternalReplaceServiceAccountReaders(native, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	mod := func(operation byte, value []byte) []byte {
		return InternalSearchBER(
			0x30,
			[]byte{10, 1, operation},
			InternalSearchBER(
				0x30,
				InternalSearchBER(4, []byte("msDS-GroupMSAMembership")),
				InternalSearchBER(0x31, InternalSearchBER(4, value)),
			),
		)
	}
	body := append(
		InternalSearchBER(4, []byte("<GUID=33221100554477668899aabbccddeeff>")),
		InternalSearchBER(0x30, mod(1, raw), mod(0, next))...)
	for _, code := range []byte{0, 16, 50} {
		t.Run(fmt.Sprintf("LDAP%d", code), func(t *testing.T) {
			fixture := InternalNewWriteWireFixture(t, 0x66, 0x67, body, nil, code)
			var counts InternalSearchNativeCounts
			wire := InternalSearchWireClient(
				t,
				&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
				InternalCountedSearchAPI(&counts),
			)
			client, s := InternalNewServiceAccountTestClient(t)
			object := InternalServiceAccountTestEntry(admodel.ServiceAccountGroupManaged)
			object.Attributes["msds-groupmsamembership"] = [][]byte{raw}
			s.InternalObjects[strings.ToLower(object.DistinguishedName)] = object
			bridge := &InternalServiceAccountNativeTestSession{
				InternalServiceAccountTestSession: s,
				InternalNative:                    (*adengine.InternalClientSessionPointer(wire)).(*adengine.InternalLdapSession),
			}
			(*adengine.InternalClientSessionPointer(client)) = bridge
			s.InternalFinish = bridge.InternalNative.InternalClose
			empty := []admodel.Identity{}
			result, err := adservice_service_accounts.New(client).
				UpdateServiceAccount(context.Background(), admodel.UpdateServiceAccountRequest{Identity: InternalObjectTestIdentity(), PasswordReaders: &empty})
			if bridge.InternalCalls != 1 {
				t.Fatal(bridge.InternalCalls)
			}
			if code == 0 {
				if err != nil || !result.Mutation.Verified || result.Account == nil ||
					len(result.Account.PasswordReaders) != 0 {
					t.Fatal(result, err)
				}
			} else {
				var ldapErr *admodel.LDAPError
				if !errors.As(err, &ldapErr) || ldapErr.Code != uint32(code) ||
					result.Mutation.State != admodel.ObjectWriteRejected {
					t.Fatal(result, err)
				}
			}
			if err = client.Close(); err != nil {
				t.Fatal(err)
			}
			if counts != (InternalSearchNativeCounts{}) {
				t.Fatal(counts)
			}
		})
	}
}

func TestNativeComputerServiceAccountAssociationWire(t *testing.T) {
	const dn = "CN=svc-東京,DC=example"
	body := append(
		InternalSearchBER(4, []byte("<GUID=33221100554477668899aabbccddeeff>")),
		InternalSearchBER(
			0x30,
			InternalSearchBER(
				0x30,
				[]byte{10, 1, 0},
				InternalSearchBER(
					0x30,
					InternalSearchBER(4, []byte("msDS-HostServiceAccount")),
					InternalSearchBER(0x31, InternalSearchBER(4, []byte(dn))),
				),
			),
		)...)
	controls := InternalSearchBER(
		0xa0,
		InternalSearchBER(
			0x30,
			InternalSearchBER(4, []byte("1.2.840.113556.1.4.1413")),
			[]byte{1, 1, 255},
			InternalSearchBER(4, nil),
		),
	)
	for _, code := range []byte{0, 20, 50} {
		t.Run(fmt.Sprintf("LDAP%d", code), func(t *testing.T) {
			fixture := InternalNewWriteWireFixture(t, 0x66, 0x67, body, controls, code)
			var counts InternalSearchNativeCounts
			wire := InternalSearchWireClient(
				t,
				&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
				InternalCountedSearchAPI(&counts),
			)
			client, s := InternalNewServiceAccountTestClient(t)
			computer := InternalComputerTestEntry(4096)
			s.InternalObjects[strings.ToLower(computer.DistinguishedName)] = computer
			account := InternalServiceAccountTestEntry(admodel.ServiceAccountStandalone)
			account.DistinguishedName = dn
			account.Attributes["objectguid"] = [][]byte{make([]byte, 16)}
			s.InternalObjects[strings.ToLower(dn)] = account
			bridge := &InternalServiceAccountNativeTestSession{
				InternalServiceAccountTestSession: s,
				InternalNative:                    (*adengine.InternalClientSessionPointer(wire)).(*adengine.InternalLdapSession),
			}
			(*adengine.InternalClientSessionPointer(client)) = bridge
			s.InternalFinish = bridge.InternalNative.InternalClose
			identity, _ := admodel.IdentityByDN(dn)
			result, err := adservice_service_accounts.New(client).
				AddComputerServiceAccounts(context.Background(), admodel.ComputerServiceAccountRequest{Computer: InternalObjectTestIdentity(), Accounts: []admodel.Identity{identity}, Permissive: true})
			if bridge.InternalCalls != 1 {
				t.Fatal(bridge.InternalCalls)
			}
			if code == 0 {
				if err != nil || !result.Mutation.Verified {
					t.Fatal(result, err)
				}
			} else {
				var ldapErr *admodel.LDAPError
				if !errors.As(err, &ldapErr) || ldapErr.Code != uint32(code) ||
					result.Mutation.State != admodel.ObjectWriteRejected {
					t.Fatal(result, err)
				}
			}
			if err = client.Close(); err != nil {
				t.Fatal(err)
			}
			if counts != (InternalSearchNativeCounts{}) {
				t.Fatal(counts)
			}
		})
	}
}

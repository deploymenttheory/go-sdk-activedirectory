package acceptance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	serviceaccounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/service_accounts"
	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

func TestPortableServiceAccountReadersUseExactOldValueCAS(t *testing.T) {
	for _, mode := range []string{"accepted", "stale", "denied", "lost", "malformed", "cancelled", "partial-readback"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newPortableReaderDescriptorFixture(t)
			certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
			received := make(chan struct{})
			steps := []portableLDAPStep{
				portableLDAPBind(0), fixture.root(), fixture.account(fixture.before, false), fixture.reader(),
				func(connection net.Conn, request *ber.Packet) error {
					if err := fixture.checkCAS(request); err != nil {
						return err
					}
					close(received)
					return portableReaderWriteResponse(connection, request, mode)
				},
			}
			if mode == "accepted" || mode == "partial-readback" {
				steps = append(steps, fixture.account(fixture.after, mode == "partial-readback"))
			}
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, steps...)
			session, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "cancelled" {
				go func() {
					select {
					case <-received:
						cancel()
					case <-ctx.Done():
					}
				}()
			}
			readers := []admodel.Identity{fixture.readerIdentity}
			result, err := serviceaccounts.New(client).UpdateServiceAccount(ctx, admodel.UpdateServiceAccountRequest{
				Identity: fixture.identity, PasswordReaders: &readers,
			})
			portableCheckReaderCASOutcome(t, mode, result, err)
			if mode == "lost" || mode == "malformed" || mode == "cancelled" {
				attempt := session.(admodel.InternalLdapWriteSession).InternalLdapWrite(t.Context(), admodel.InternalLdapWriteRequest{
					InternalOperation: admodel.InternalLdapWriteDelete, InternalDn: admodel.InternalObjectGUIDTarget(fixture.guid),
				})
				if attempt.State != admodel.InternalLdapWriteNotAttempted || !errors.Is(attempt.Err, admodel.ErrClosed) {
					t.Fatal("failed CAS session permitted another mutation", attempt)
				}
			}
			_ = client.Close()
			wire.wait(t)
			want := int32(5)
			if mode == "accepted" || mode == "partial-readback" {
				want++
			}
			if wire.requests.Load() != want {
				t.Fatal("CAS was retried or rejected/uncertain effect was read back", wire.requests.Load())
			}
		})
	}
}

func TestPortableServiceAccountRawMissingAttributeIsNotReaderConflict(t *testing.T) {
	for _, compound := range []bool{false, true} {
		t.Run(fmt.Sprint(compound), func(t *testing.T) {
			fixture := newPortableReaderDescriptorFixture(t)
			certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
			steps := []portableLDAPStep{portableLDAPBind(0), fixture.root(), fixture.account(fixture.before, false)}
			request := admodel.UpdateServiceAccountRequest{
				Identity: fixture.identity,
				Changes: []admodel.AttributeChange{{
					Attribute: "description", Kind: admodel.AttributeRemoveValues,
					Values: []admodel.RawValue{admodel.NewRawValue([]byte("missing"))},
				}},
			}
			if compound {
				readers := []admodel.Identity{fixture.readerIdentity}
				request.PasswordReaders = &readers
				steps = append(steps, fixture.reader())
			}
			steps = append(steps, func(connection net.Conn, packet *ber.Packet) error {
				return portableReaderWriteResponse(connection, packet, "stale")
			})
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, steps...)
			_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
			result, err := serviceaccounts.New(client).UpdateServiceAccount(t.Context(), request)
			var response *admodel.LDAPError
			if !errors.As(err, &response) || response.Code != 16 || errors.Is(err, admodel.ErrObjectConcurrency) ||
				result.Mutation.State != admodel.ObjectWriteRejected {
				t.Fatal("unrelated missing attribute was mistaken for a reader CAS conflict", err)
			}
			_ = client.Close()
			wire.wait(t)
			if wire.requests.Load() != int32(len(steps)) {
				t.Fatal("rejected raw removal was retried or read back")
			}
		})
	}
}

func portableCheckReaderCASOutcome(t *testing.T, mode string, result admodel.ServiceAccountMutationResult, err error) {
	t.Helper()
	mutation := result.Mutation
	if mutation.Before == nil || mutation.TargetGUID == nil {
		t.Fatal("CAS lost its preflight identity and descriptor", err)
	}
	switch mode {
	case "accepted":
		if err != nil || mutation.State != admodel.ObjectWriteAccepted || !mutation.Verified || result.Account == nil ||
			len(result.Account.PasswordReaders) != 1 || result.Account.PasswordReaders[0].String() != "S-1-5-21-1-2-3-1101" {
			t.Fatal("accepted portable reader update failed verification", mutation, err)
		}
	case "partial-readback":
		if !errors.Is(err, admodel.ErrObjectReadback) || mutation.State != admodel.ObjectWriteAccepted || mutation.Verified ||
			len(mutation.ReadbackCandidates) != 1 {
			t.Fatal("accepted effect or partial readback observation was lost", mutation, err)
		}
	case "stale", "denied":
		code, sentinel := uint32(16), admodel.ErrObjectConcurrency
		if mode == "denied" {
			code, sentinel = 50, admodel.ErrObjectWritePermission
		}
		var response *admodel.LDAPError
		if !errors.Is(err, sentinel) || !errors.As(err, &response) || response.Code != code ||
			mutation.State != admodel.ObjectWriteRejected || mutation.Verified {
			t.Fatal("actual strict CAS refusal lost its outcome or status", mutation, err)
		}
	default:
		if !errors.Is(err, admodel.ErrObjectWriteUncertain) || mutation.State != admodel.ObjectWriteUncertain || mutation.Verified {
			t.Fatal("submitted interrupted CAS did not remain uncertain", mutation, err)
		}
	}
}

func portableReaderWriteResponse(connection net.Conn, request *ber.Packet, mode string) error {
	tag, code := ber.Tag(ldap.ApplicationModifyResponse), int64(0)
	switch mode {
	case "lost":
		return io.EOF
	case "cancelled":
		_, err := io.Copy(io.Discard, connection)
		return err
	case "malformed":
		tag = ldap.ApplicationAddResponse
	case "stale":
		code = 16
	case "denied":
		code = 50
	}
	_, err := connection.Write(portableLDAPResult(request, tag, code).Bytes())
	return err
}

type portableReaderDescriptorFixture struct {
	identity, readerIdentity admodel.Identity
	guid                     admodel.GUID
	before, after            []byte
	readerSID                admodel.SID
}

func newPortableReaderDescriptorFixture(t *testing.T) portableReaderDescriptorFixture {
	t.Helper()
	f := portableReaderDescriptorFixture{}
	var err error
	f.identity, err = admodel.IdentityByDN("CN=owned,DC=ad,DC=sdk,DC=test")
	if err != nil {
		t.Fatal(err)
	}
	f.readerIdentity, err = admodel.IdentityByDN("CN=reader,DC=ad,DC=sdk,DC=test")
	if err != nil {
		t.Fatal(err)
	}
	f.guid, err = admodel.GUIDFromBytes(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	f.readerSID, err = admodel.ParseSID("S-1-5-21-1-2-3-1101")
	if err != nil {
		t.Fatal(err)
	}
	// Only the ordinary explicit RP bits are owned. The mixed WP grant, deny,
	// callback, opaque ACE, inherited grant and all non-DACL storage must survive.
	descriptor, err := conditions.ParseSDDL(`O:SYG:BAD:PAI(D;;RP;;;BU)(A;;RPWP;;;SY)(XA;;RP;;;WD;(@User.Department == "Finance"))(A;ID;RP;;;BA)S:(AU;SA;RP;;;WD)`)
	if err != nil {
		t.Fatal(err)
	}
	acl := descriptor.DACL()
	acl.ACEs = append(acl.ACEs[:3:3], append([][]byte{{0x7f, 0, 8, 0, 0x42, 0xa5, 0xff, 0}}, acl.ACEs[3:]...)...)
	descriptor, err = descriptor.WithDACL(acl)
	if err != nil {
		t.Fatal(err)
	}
	f.before, err = descriptor.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// Construct the expected edit independently of the service-account editor.
	acl.ACEs[1] = bytes.Clone(acl.ACEs[1])
	acl.ACEs[1][4] = 0x20
	grant, err := conditions.ParseSDDL("D:(A;;RP;;;" + f.readerSID.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	acl.ACEs = append(acl.ACEs[:4:4], append(grant.DACL().ACEs, acl.ACEs[4:]...)...)
	edited, err := descriptor.WithDACL(acl)
	if err != nil {
		t.Fatal(err)
	}
	f.after, err = edited.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f portableReaderDescriptorFixture) root() portableLDAPStep {
	return func(connection net.Conn, request *ber.Packet) error {
		if request.Children[1].Children[0].Value != "" {
			return fmt.Errorf("reader update omitted RootDSE discovery")
		}
		return portableReaderSearchResponse(connection, request, "", map[string][][]byte{
			"supportedCapabilities": {[]byte(admodel.CapabilityActiveDirectory)},
			"defaultNamingContext":  {[]byte("DC=ad,DC=sdk,DC=test")}, "namingContexts": {[]byte("DC=ad,DC=sdk,DC=test")},
		}, false, false)
	}
}

func (f portableReaderDescriptorFixture) account(raw []byte, partial bool) portableLDAPStep {
	return func(connection net.Conn, request *ber.Packet) error {
		return portableReaderSearchResponse(connection, request, f.identity.String(), map[string][][]byte{
			"objectGUID": {f.guid.Bytes()}, "objectClass": {[]byte("user"), []byte("computer"), []byte("msDS-GroupManagedServiceAccount")},
			"userAccountControl": {[]byte("4098")}, "uSNChanged": {[]byte("7")}, "msDS-GroupMSAMembership": {raw},
		}, true, partial)
	}
}

func (f portableReaderDescriptorFixture) reader() portableLDAPStep {
	return func(connection net.Conn, request *ber.Packet) error {
		if request.Children[1].Children[0].Value != f.readerIdentity.String() {
			return fmt.Errorf("retrieval reader identity was not resolved")
		}
		return portableReaderSearchResponse(connection, request, f.readerIdentity.String(), map[string][][]byte{
			"objectSid": {f.readerSID.Bytes()}, "objectClass": {[]byte("computer")},
		}, true, false)
	}
}

func portableReaderSearchResponse(connection net.Conn, request *ber.Packet, dn string, attrs map[string][][]byte, paged, partial bool) error {
	if request.Children[1].Tag != ldap.ApplicationSearchRequest {
		return fmt.Errorf("descriptor discovery was not a search")
	}
	var controls []ldap.Control
	if paged {
		if _, _, err := portableLDAPPaging(request); err != nil {
			return err
		}
		controls = []ldap.Control{&ldap.ControlPaging{}}
	}
	entry := portableLDAPEntry(request, attrs)
	entry.Children[1].Children[0] = ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "")
	// Rebuild the protocol bytes after replacing the entry DN.
	protocol := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "")
	for _, child := range entry.Children[1].Children {
		protocol.AppendChild(child)
	}
	if _, err := connection.Write(portableLDAPEnvelope(request, protocol).Bytes()); err != nil {
		return err
	}
	code := int64(0)
	if partial {
		code = 50
	}
	_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, code, controls...).Bytes())
	return err
}

func (f portableReaderDescriptorFixture) checkCAS(request *ber.Packet) error {
	if len(request.Children) != 2 {
		return fmt.Errorf("whole-value CAS incorrectly used SD-flags, permissive or assertion controls")
	}
	protocol := request.Children[1]
	if protocol.Tag != ldap.ApplicationModifyRequest || len(protocol.Children) != 2 || protocol.Children[0].Value != admodel.InternalObjectGUIDTarget(f.guid) {
		return fmt.Errorf("reader CAS lost its GUID target or Modify shape")
	}
	changes := protocol.Children[1].Children
	if len(changes) != 2 {
		return fmt.Errorf("reader CAS was not one strict delete/add operation")
	}
	for i, want := range [][]byte{f.before, f.after} {
		change := changes[i]
		if len(change.Children) != 2 || change.Children[0].Value != int64(1-i) {
			return fmt.Errorf("reader CAS operation order changed")
		}
		attribute := change.Children[1].Children
		if len(attribute) != 2 || attribute[0].Value != "msDS-GroupMSAMembership" || len(attribute[1].Children) != 1 ||
			!bytes.Equal(attribute[1].Children[0].Data.Bytes(), want) {
			return fmt.Errorf("reader CAS lost exact old bytes or changed unrelated descriptor state")
		}
	}
	return nil
}

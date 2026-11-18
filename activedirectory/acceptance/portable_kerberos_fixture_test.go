package acceptance

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/asn1tools"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	krbgss "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/gssapi"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/keyusage"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3/gssapi"
)

func portableKerberosTLSCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{portableTLSHost}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: key, Leaf: leaf}, roots
}

type portableKerberosAcceptor struct {
	kdc           *portableKerberosKDC
	binding       [16]byte
	authenticator types.Authenticator
	key           types.EncryptionKey
}

func newPortableKerberosAcceptor(t *testing.T, kdc *portableKerberosKDC, certificate *x509.Certificate) *portableKerberosAcceptor {
	t.Helper()
	binding, err := gssapi.ComputeChannelBindingHash(gssapi.CertificateHash(certificate))
	if err != nil {
		t.Fatal(err)
	}
	etype, err := crypto.GetEtype(18)
	if err != nil {
		t.Fatal(err)
	}
	key, err := types.GenerateEncryptionKey(etype)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(key.KeyValue) })
	return &portableKerberosAcceptor{kdc: kdc, binding: binding, key: key}
}

func portableKerberosRequestToken(request *ber.Packet) ([]byte, error) {
	if len(request.Children) != 2 || request.Children[1].Tag != ldap.ApplicationBindRequest {
		return nil, errors.New("owned Kerberos fixture received a non-bind operation")
	}
	bind := request.Children[1]
	if len(bind.Children) != 3 || bind.Children[2].ClassType != ber.ClassContext || bind.Children[2].Tag != 3 || len(bind.Children[2].Children) < 1 ||
		bind.Children[2].Children[0].Data.String() != "GSSAPI" {
		return nil, errors.New("Kerberos bind attempted a different authentication mechanism")
	}
	if len(bind.Children[2].Children) == 1 {
		return nil, nil
	}
	return append([]byte(nil), bind.Children[2].Children[1].Data.Bytes()...), nil
}

func portableKerberosBindReply(conn net.Conn, request *ber.Packet, code int64, token []byte) error {
	response := portableLDAPResult(request, ldap.ApplicationBindResponse, code)
	if token != nil {
		credentials := ber.Encode(ber.ClassContext, ber.TypePrimitive, 7, nil, "")
		credentials.Data.Write(token)
		response.Children[1].AppendChild(credentials)
	}
	_, err := conn.Write(portableLDAPEnvelope(request, response.Children[1]).Bytes())
	return err
}

func (a *portableKerberosAcceptor) authenticate(conn net.Conn, request *ber.Packet) error {
	wire, err := portableKerberosRequestToken(request)
	if err != nil {
		return err
	}
	var envelope asn1.RawValue
	remaining, err := asn1.Unmarshal(wire, &envelope)
	if err != nil || len(remaining) != 0 {
		return errors.New("owned Kerberos AP request envelope is malformed")
	}
	var oid asn1.ObjectIdentifier
	inner, err := asn1.Unmarshal(envelope.Bytes, &oid)
	if err != nil || !oid.Equal(krbgss.OIDKRB5.OID()) || len(inner) < 2 || binary.LittleEndian.Uint16(inner[:2]) != 1 {
		return errors.New("owned Kerberos AP request changed mechanism")
	}
	var ap messages.APReq
	if err := ap.Unmarshal(inner[2:]); err != nil {
		return err
	}
	if ok, err := ap.Verify(a.kdc.keys, 5*time.Minute, types.HostAddress{}, nil); err != nil || !ok {
		return errors.New("owned Kerberos AP request did not authenticate")
	}
	a.authenticator = ap.Authenticator
	checksum := a.authenticator.Cksum.Checksum
	if len(checksum) != 24 || binary.LittleEndian.Uint32(checksum[:4]) != 16 || !bytes.Equal(checksum[4:20], a.binding[:]) {
		return errors.New("actual Kerberos authenticator omitted or changed certificate-derived channel binding")
	}
	part := messages.EncAPRepPart{CTime: a.authenticator.CTime, Cusec: a.authenticator.Cusec, Subkey: a.key, SequenceNumber: 712}
	plain, err := asn1.Marshal(part)
	if err != nil {
		return err
	}
	plain = asn1tools.AddASNAppTag(plain, 27)
	defer clear(plain)
	encrypted, err := crypto.GetEncryptedData(plain, ap.Ticket.DecryptedEncPart.Key, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		return err
	}
	reply := messages.APRep{PVNO: 5, MsgType: 15, EncPart: encrypted}
	encoded, err := asn1.Marshal(reply)
	if err != nil {
		return err
	}
	encoded = asn1tools.AddASNAppTag(encoded, 15)
	oidWire, err := asn1.Marshal(krbgss.OIDKRB5.OID())
	if err != nil {
		return err
	}
	token, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassApplication, Tag: 0, IsCompound: true, Bytes: append(append(oidWire, 2, 0), encoded...)})
	if err != nil {
		return err
	}
	return portableKerberosBindReply(conn, request, 14, token)
}

func (a *portableKerberosAcceptor) offer(conn net.Conn, request *ber.Packet) error {
	wire, err := portableKerberosRequestToken(request)
	if err != nil || len(wire) != 0 {
		return errors.New("owned Kerberos security-layer offer received an unexpected client token")
	}
	token := &krbgss.WrapToken{Flags: 5, EC: 12, SndSeqNum: 712, Payload: []byte{1, 0, 0, 0}}
	if err := token.SetCheckSum(a.key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		return err
	}
	wire, err = token.Marshal()
	if err != nil {
		return err
	}
	return portableKerberosBindReply(conn, request, 14, wire)
}

func (a *portableKerberosAcceptor) accept(conn net.Conn, request *ber.Packet) error {
	wire, err := portableKerberosRequestToken(request)
	if err != nil {
		return err
	}
	var token krbgss.WrapToken
	if err := token.Unmarshal(wire, false); err != nil {
		return err
	}
	if ok, err := token.Verify(a.key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil || !ok {
		return errors.New("owned Kerberos security-layer response failed integrity")
	}
	if token.SndSeqNum != uint64(a.authenticator.SeqNumber) || token.Flags != 4 || !bytes.Equal(token.Payload, []byte{1, 0, 0, 0}) {
		return errors.New("owned Kerberos response changed the authenticated sequence or selected layer")
	}
	return portableKerberosBindReply(conn, request, 0, nil)
}

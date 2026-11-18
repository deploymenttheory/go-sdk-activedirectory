package acceptance

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestPortableKerberosActualServiceExpiryRetiresBlockedReadAndPreventsWrite(t *testing.T) {
	certificate, roots := portableKerberosTLSCertificate(t)
	kdc := newPortableKerberosKDC(t)
	acceptor := newPortableKerberosAcceptor(t, kdc, certificate.Leaf)
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, acceptor.authenticate, acceptor.offer, acceptor.accept,
		func(conn net.Conn, request *ber.Packet) error { _, err := io.Copy(io.Discard, conn); return err })
	end := time.Now().Add(2 * time.Second)
	data := portableKerberosCacheFile(t, kdc, portableKerberosUser, true, end)
	defer clear(data)
	path := filepath.Join(t.TempDir(), "owned-expiring.ccache")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	options := portableTLSConfig(admodel.TransportLDAPS, roots)
	options.Authentication = admodel.AuthenticationKerberos
	options.Credentials = nil
	options.Kerberos = &admodel.KerberosCredentials{
		Source: admodel.KerberosCredentialCacheFile, Username: portableKerberosUser, Realm: portableKerberosRealm,
		SPN: "ldap/" + portableTLSHost, CachePath: path,
	}
	session, err := adengine.InternalDialPortableWithDial(t.Context(), options, portableKerberosDialer{ldap: wire, kdc: kdc})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.InternalClose() })
	attributes, err := session.InternalBaseObject(t.Context(), "CN=owned,DC=ad,DC=sdk,DC=test", []string{"name"})
	if len(attributes) != 0 || !errors.Is(err, admodel.ErrKerberosExpired) {
		t.Fatalf("expired blocked read returned usable success or lost expiry: %v", err)
	}
	writer := session.(interface {
		InternalLdapWrite(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt
	})
	attempt := writer.InternalLdapWrite(
		t.Context(),
		admodel.InternalLdapWriteRequest{InternalOperation: admodel.InternalLdapWriteDelete, InternalDn: "CN=owned,DC=ad,DC=sdk,DC=test"},
	)
	if attempt.State != admodel.InternalLdapWriteNotAttempted || attempt.Err == nil {
		t.Fatalf("expired session submitted a write: %+v", attempt)
	}
	if kdc.requests.Load() != 0 || wire.requests.Load() != 4 {
		t.Fatal("expired context renewed credentials or replayed an operation")
	}
	wire.wait(t)
}

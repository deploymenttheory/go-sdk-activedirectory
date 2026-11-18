package acceptance

import (
	"context"
	"errors"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestPortableKerberosCancellationDuringKDCExchangeRetiresBothOwnedSockets(t *testing.T) {
	certificate, roots := portableKerberosTLSCertificate(t)
	kdc := newPortableKerberosKDC(t, func(k *portableKerberosKDC) { k.stallAS = true })
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate)
	options := portableTLSConfig(admodel.TransportLDAPS, roots)
	options.Authentication, options.Credentials = admodel.AuthenticationKerberos, nil
	options.Kerberos = portableKerberosSource(t, kdc, admodel.KerberosPassword, false)
	ctx, cancel := context.WithCancelCause(t.Context())
	t.Cleanup(func() { cancel(context.Canceled) })
	completed := make(chan error, 1)
	go func() {
		session, err := adengine.InternalDialPortableWithDial(ctx, options, portableKerberosDialer{ldap: wire, kdc: kdc})
		if session != nil {
			_ = session.InternalClose()
			completed <- errors.New("cancelled authentication returned a session")
			return
		}
		completed <- err
	}()
	select {
	case <-kdc.started:
	case <-time.After(3 * time.Second):
		t.Fatal("owned KDC did not receive the real AS request")
	}
	want := errors.New("owned Kerberos cancellation")
	cancel(want)
	select {
	case err := <-completed:
		if !errors.Is(err, want) {
			t.Fatalf("authentication lost caller cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("KDC work or LDAP bind gate outlived cancellation")
	}
	wire.wait(t)
	if kdc.requests.Load() != 1 || wire.requests.Load() != 0 {
		t.Fatal("cancelled Kerberos authentication retried or submitted LDAP credentials")
	}
}

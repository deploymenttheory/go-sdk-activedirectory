package acceptance

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestPortableLDAPCloseCancelsActiveSearchAndRetiresOnce(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	started := make(chan struct{})
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, portableLDAPBind(0), func(connection net.Conn, request *ber.Packet) error {
		close(started)
		_, err := io.Copy(io.Discard, connection)
		return err
	})
	_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	type observation struct {
		result admodel.SearchResult
		err    error
	}
	completed := make(chan observation, 1)
	go func() {
		result, err := client.Search(t.Context(), admodel.SearchOptions{Base: "DC=ad,DC=sdk,DC=test", Scope: admodel.ScopeSubtree})
		completed <- observation{result, err}
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("owned search did not submit")
	}
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal("close active search:", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not retire a blocked portable socket")
	}
	select {
	case got := <-completed:
		if got.result.Complete || got.err == nil || !errors.Is(got.err, admodel.ErrClosed) {
			t.Fatalf("closed search became complete: %+v %v", got.result, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("portable reader outlived Close")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	wire.wait(t)
}

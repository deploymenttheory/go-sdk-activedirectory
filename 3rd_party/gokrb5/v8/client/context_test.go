package client_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/config"
)

func TestLoginCancellationRetiresActualKDCConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	request := make(chan struct{})
	retired := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			retired <- acceptErr
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		var header [4]byte
		if _, readErr := io.ReadFull(conn, header[:]); readErr != nil {
			retired <- readErr
			return
		}
		close(request)
		_, readErr := io.Copy(io.Discard, conn)
		retired <- readErr
	}()
	ctx, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(context.Canceled) })
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = "EXAMPLE.TEST"
	cfg.LibDefaults.UDPPreferenceLimit = 1
	cfg.Realms = []config.Realm{{Realm: "EXAMPLE.TEST", KDC: []string{listener.Addr().String()}}}
	cl := client.NewWithPassword("owned-fixture", "EXAMPLE.TEST", "fixture-only", cfg, client.WithContext(ctx))
	t.Cleanup(cl.Destroy)
	result := make(chan error, 1)
	go func() { result <- cl.Login() }()
	select {
	case <-request:
	case <-time.After(3 * time.Second):
		t.Fatal("KDC did not receive the real AS request")
	}
	want := errors.New("owned authentication cancelled")
	cancel(want)
	select {
	case got := <-result:
		if !errors.Is(got, want) {
			t.Fatalf("Login cause = %v; want caller cancellation", got)
		}
	case <-time.After(time.Second):
		t.Fatal("Login kept KDC work running after cancellation")
	}
	select {
	case err := <-retired:
		if err != nil {
			t.Fatalf("owned KDC connection was not cleanly retired: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled Login left its KDC connection open")
	}
}

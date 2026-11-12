package activedirectory

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testSession struct {
	read   func(context.Context, []string) (map[string][][]byte, error)
	search func(context.Context, SearchOptions) (searchCursor, error)
	finish func() error
}

func (s testSession) rootDSE(ctx context.Context, properties []string) (map[string][][]byte, error) {
	return s.read(ctx, properties)
}
func (s testSession) close() error { return s.finish() }
func (s testSession) startSearch(ctx context.Context, options SearchOptions) (searchCursor, error) {
	return s.search(ctx, options)
}

func TestCloseCancelsReadBeforeUnbinding(t *testing.T) {
	started := make(chan struct{})
	var active, closes atomic.Int32
	closeFailure := errors.New("injected close failure")
	client := newClient(Config{Timeout: time.Second}, testSession{
		read: func(ctx context.Context, _ []string) (map[string][][]byte, error) {
			active.Add(1)
			defer active.Add(-1)
			close(started)
			<-ctx.Done()
			return map[string][][]byte{"dnshostname": {[]byte("dc1.ad.sdk.test")}}, context.Cause(ctx)
		},
		finish: func() error {
			if active.Load() != 0 {
				t.Error("unbound while native read was active")
			}
			closes.Add(1)
			return closeFailure
		},
	})
	readDone := make(chan error, 1)
	go func() { _, err := client.RootDSE(context.Background(), RootDSEOptions{}); readDone <- err }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("read did not start")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.RootDSE(ctx, RootDSEOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("queued canceled read: %v", err)
	}
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := client.Close(); !errors.Is(err, closeFailure) {
				t.Errorf("Close: %v", err)
			}
		}()
	}
	group.Wait()
	if err := <-readDone; !errors.Is(err, ErrClosed) {
		t.Fatalf("active read: %v", err)
	}
	if closes.Load() != 1 {
		t.Fatalf("unbind count %d", closes.Load())
	}
	if _, err := client.RootDSE(context.Background(), RootDSEOptions{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("read after close: %v", err)
	}
}

func TestRootDSEPreservesPartialFailure(t *testing.T) {
	readFailure := &LDAPError{Operation: "RootDSE", Code: 3, Diagnostic: "private server details"}
	client := newClient(Config{Timeout: time.Second}, testSession{
		read: func(context.Context, []string) (map[string][][]byte, error) {
			return map[string][][]byte{"dnshostname": {[]byte("dc1.ad.sdk.test")}}, readFailure
		},
		finish: func() error { return nil },
	})
	defer client.Close()
	result, err := client.RootDSE(context.Background(), RootDSEOptions{})
	var native *LDAPError
	if result.DNSHostName == nil || *result.DNSHostName != "dc1.ad.sdk.test" || !errors.As(err, &native) || native != readFailure {
		t.Fatalf("partial result lost: %#v, %v", result, err)
	}
	if err.Error() != "RootDSE: LDAP status 3" {
		t.Fatalf("error disclosed diagnostics: %v", err)
	}
}

func TestCanceledDialDoesNotLoadNativeAPI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client, err := Dial(ctx, Config{Endpoint: Endpoint{Host: "dc1.ad.sdk.test"}})
	if client != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Dial: %v, %v", client, err)
	}
}

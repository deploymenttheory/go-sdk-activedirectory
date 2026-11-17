package acceptance

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type InternalTestSession struct {
	InternalRead   func(context.Context, []string) (map[string][][]byte, error)
	InternalSearch func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error)
	InternalBase   func(context.Context, string, []string) (map[string][][]byte, error)
	InternalRanged func(context.Context, string, []string) (map[string][][]byte, error)
	InternalFinish func() error
}

func (s InternalTestSession) InternalRangedBaseObject(
	ctx context.Context,
	base string,
	properties []string,
) (map[string][][]byte, error) {
	if s.InternalRanged != nil {
		return s.InternalRanged(ctx, base, properties)
	}
	return s.InternalBaseObject(ctx, base, properties)
}

func (s InternalTestSession) InternalBaseObject(
	ctx context.Context,
	base string,
	properties []string,
) (map[string][][]byte, error) {
	if s.InternalBase != nil {
		return s.InternalBase(ctx, base, properties)
	}
	return s.InternalRead(ctx, properties)
}
func (s InternalTestSession) InternalClose() error { return s.InternalFinish() }

func (s InternalTestSession) InternalStartSearch(
	ctx context.Context,
	options admodel.SearchOptions,
) (admodel.InternalSearchCursor, error) {
	return s.InternalSearch(ctx, options)
}

func TestCloseCancelsReadBeforeUnbinding(t *testing.T) {
	started := make(chan struct{})
	var active, closes atomic.Int32
	closeFailure := errors.New("injected close failure")
	client := adengine.InternalNewClient(admodel.Config{Timeout: time.Second}, InternalTestSession{
		InternalRead: func(ctx context.Context, _ []string) (map[string][][]byte, error) {
			active.Add(1)
			defer active.Add(-1)
			close(started)
			<-ctx.Done()
			return map[string][][]byte{
					"dnshostname": {[]byte("dc1.ad.sdk.test")},
				}, context.Cause(
					ctx,
				)
		},
		InternalFinish: func() error {
			if active.Load() != 0 {
				t.Error("unbound while native read was active")
			}
			closes.Add(1)
			return closeFailure
		},
	})
	readDone := make(chan error, 1)
	go func() { _, err := client.RootDSE(context.Background(), admodel.RootDSEOptions{}); readDone <- err }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("read did not start")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.RootDSE(ctx, admodel.RootDSEOptions{}); !errors.Is(err, context.Canceled) {
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
	if err := <-readDone; !errors.Is(err, admodel.ErrClosed) {
		t.Fatalf("active read: %v", err)
	}
	if closes.Load() != 1 {
		t.Fatalf("unbind count %d", closes.Load())
	}
	if _, err := client.RootDSE(
		context.Background(),
		admodel.RootDSEOptions{},
	); !errors.Is(
		err,
		admodel.ErrClosed,
	) {
		t.Fatalf("read after close: %v", err)
	}
}

func TestRootDSEPreservesPartialFailure(t *testing.T) {
	readFailure := &admodel.LDAPError{
		Operation:  "RootDSE",
		Code:       3,
		Diagnostic: "private server details",
	}
	client := adengine.InternalNewClient(admodel.Config{Timeout: time.Second}, InternalTestSession{
		InternalRead: func(context.Context, []string) (map[string][][]byte, error) {
			return map[string][][]byte{"dnshostname": {[]byte("dc1.ad.sdk.test")}}, readFailure
		},
		InternalFinish: func() error { return nil },
	})
	defer client.Close()
	result, err := client.RootDSE(context.Background(), admodel.RootDSEOptions{})
	var native *admodel.LDAPError
	if result.DNSHostName == nil || *result.DNSHostName != "dc1.ad.sdk.test" ||
		!errors.As(err, &native) ||
		native != readFailure {
		t.Fatalf("partial result lost: %#v, %v", result, err)
	}
	if err.Error() != "RootDSE: LDAP status 3" {
		t.Fatalf("error disclosed diagnostics: %v", err)
	}
}

func TestCanceledDialDoesNotLoadNativeAPI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client, err := adengine.Dial(
		ctx,
		admodel.Config{Endpoint: admodel.Endpoint{Host: "dc1.ad.sdk.test"}},
	)
	if client != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Dial: %v, %v", client, err)
	}
}

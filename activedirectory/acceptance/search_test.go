package acceptance

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type InternalTestSearchCursor struct {
	InternalRead   func(context.Context, uint32) ([]admodel.Object, bool, error)
	InternalFinish func() error
}

func (c InternalTestSearchCursor) InternalNext(
	ctx context.Context,
	size uint32,
) ([]admodel.Object, bool, error) {
	return c.InternalRead(ctx, size)
}
func (c InternalTestSearchCursor) InternalClose() error { return c.InternalFinish() }

func TestSearchSelectionValidationAndAttributeState(t *testing.T) {
	for _, options := range []admodel.SearchOptions{{Scope: 3}, {PageSize: -1}, {ResultLimit: -1}, {Base: "a\x00b"}, {Filter: "(a=\x00)"}, {Properties: []string{"name)"}}, {Properties: []string{"1.1", "name"}}} {
		if options.Validate() == nil {
			t.Fatalf("accepted %#v", options)
		}
	}
	options, err := admodel.InternalSearchOptionsNormalized(
		(admodel.SearchOptions{Properties: []string{"ObjectGUID", "objectguid", "description", "*"}}),
	)
	if err != nil ||
		!reflect.DeepEqual(options.Properties, []string{"ObjectGUID", "description", "*"}) ||
		options.PageSize != 256 ||
		options.Filter != "(objectClass=*)" {
		t.Fatalf("%#v %v", options, err)
	}
	object := admodel.Object{
		Attributes: map[string][][]byte{
			"objectguid":          {{0, 255, 128}},
			"member;range=0-1499": {[]byte("CN=first")},
		},
		RequestedProperties: options.Properties,
	}
	values, state := object.Attribute("OBJECTGUID")
	if state != admodel.AttributePresent || !reflect.DeepEqual(values, [][]byte{{0, 255, 128}}) {
		t.Fatal("binary attribute changed")
	}
	for name, want := range map[string]admodel.AttributeState{"description": admodel.AttributeAbsent, "canonicalName": admodel.AttributeUnloaded, "member": admodel.AttributePartial} {
		if _, got := object.Attribute(name); got != want {
			t.Fatalf("%s state %d, want %d", name, got, want)
		}
	}
}

func TestSearchCollectsThroughEmptyPagesAndHonorsLimits(t *testing.T) {
	for _, tc := range []struct {
		InternalName     string
		InternalCounts   []int
		InternalLimit    int
		InternalWant     int
		InternalComplete bool
	}{
		{"zero", nil, 0, 0, true},
		{"one", []int{1}, 0, 1, true},
		{"many", []int{2, 0, 2, 1}, 0, 5, true},
		{"first", []int{1}, 1, 1, false},
		{"page boundary", []int{2}, 2, 2, false},
		{"within page", []int{2, 1}, 3, 3, false},
	} {
		t.Run(tc.InternalName, func(t *testing.T) {
			calls, closes := 0, 0
			cursor := InternalTestSearchCursor{
				InternalRead: func(_ context.Context, size uint32) ([]admodel.Object, bool, error) {
					if calls == len(tc.InternalCounts) {
						calls++
						return nil, true, nil
					}
					n := tc.InternalCounts[calls]
					calls++
					if n > int(size) {
						t.Fatalf("page request too small: %d", size)
					}
					return make([]admodel.Object, n), false, nil
				},
				InternalFinish: func() error { closes++; return nil },
			}
			result, err := admodel.InternalCollectSearch(
				context.Background(),
				cursor,
				admodel.SearchOptions{
					PageSize:    2,
					ResultLimit: tc.InternalLimit,
					Properties:  []string{"name"},
				},
			)
			if err != nil || len(result.Objects) != tc.InternalWant ||
				result.Complete != tc.InternalComplete ||
				result.LimitReached == tc.InternalComplete ||
				closes != 1 {
				t.Fatalf("%+v %v closes=%d", result, err, closes)
			}
			wantCalls := len(tc.InternalCounts)
			if tc.InternalComplete {
				wantCalls++
			}
			if calls != wantCalls {
				t.Fatalf("called next %d times, want %d", calls, wantCalls)
			}
			for _, object := range result.Objects {
				if _, state := object.Attribute("name"); state != admodel.AttributeAbsent {
					t.Fatal("selection lost")
				}
			}
		})
	}
}

func TestSearchPreservesPartialErrorAndCleanupFailure(t *testing.T) {
	for _, code := range []uint32{3, 4, 32, 50, 12} {
		t.Run((&admodel.LDAPError{Operation: "Search", Code: code}).Error(), func(t *testing.T) {
			cause := &admodel.LDAPError{
				Operation:  "Search",
				Code:       code,
				Diagnostic: "private server detail",
				MatchedDN:  "DC=example",
			}
			cleanup := errors.New("injected cleanup failure")
			client := adengine.InternalNewClient(
				admodel.Config{Timeout: time.Second},
				InternalTestSession{
					InternalSearch: func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
						return InternalTestSearchCursor{
							InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
								return []admodel.Object{
									{DistinguishedName: "CN=partial"},
								}, false, cause
							},
							InternalFinish: func() error { return cleanup },
						}, nil
					},
					InternalFinish: func() error { return nil },
				},
			)
			defer client.Close()
			result, err := client.Search(context.Background(), admodel.SearchOptions{})
			var partial *admodel.SearchError
			var native *admodel.LDAPError
			if !errors.As(err, &partial) || partial.Returned != 1 || !errors.As(err, &native) ||
				native != cause ||
				!errors.Is(err, cleanup) ||
				!errors.Is(err, admodel.ErrIncompleteResult) ||
				result.Complete {
				t.Fatalf("%+v %v", result, err)
			}
		})
	}
}

func TestSearchCancellationBetweenPages(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls, closes := 0, 0
	result, err := admodel.InternalCollectSearch(
		ctx,
		InternalTestSearchCursor{
			InternalRead: func(context.Context, uint32) ([]admodel.Object, bool, error) {
				calls++
				cancel()
				return []admodel.Object{{DistinguishedName: "CN=partial"}}, false, nil
			},
			InternalFinish: func() error { closes++; return nil },
		},
		admodel.SearchOptions{PageSize: 2},
	)
	if !errors.Is(err, context.Canceled) || len(result.Objects) != 1 || calls != 1 || closes != 1 {
		t.Fatalf("%+v %v calls=%d closes=%d", result, err, calls, closes)
	}
}

func TestCloseCancelsSearchAndWaitsForPageCleanup(t *testing.T) {
	started, cleaned := make(chan struct{}), make(chan struct{})
	client := adengine.InternalNewClient(
		admodel.Config{Timeout: time.Second},
		InternalTestSession{
			InternalSearch: func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				return InternalTestSearchCursor{
					InternalRead: func(ctx context.Context, _ uint32) ([]admodel.Object, bool, error) {
						close(started)
						<-ctx.Done()
						return nil, false, context.Cause(ctx)
					},
					InternalFinish: func() error { close(cleaned); return nil },
				}, nil
			},
			InternalFinish: func() error {
				select {
				case <-cleaned:
				default:
					t.Error("unbind preceded page cleanup")
				}
				return nil
			},
		},
	)
	done := make(chan error, 1)
	go func() { _, err := client.Search(context.Background(), admodel.SearchOptions{}); done <- err }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("search did not start")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, admodel.ErrClosed) ||
		!errors.Is(err, admodel.ErrIncompleteResult) {
		t.Fatal(err)
	}
	if _, err := client.Search(
		context.Background(),
		admodel.SearchOptions{},
	); !errors.Is(
		err,
		admodel.ErrClosed,
	) {
		t.Fatal(err)
	}
}

func TestQueuedSearchTimeoutLeavesActiveCleanupAndCloseOrdered(t *testing.T) {
	cleanupStarted, releaseCleanup, cleaned := make(
		chan struct{},
	), make(
		chan struct{},
	), make(
		chan struct{},
	)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseCleanup) }) }
	var searches atomic.Int32
	client := adengine.InternalNewClient(
		admodel.Config{Timeout: 60 * time.Millisecond},
		InternalTestSession{
			InternalSearch: func(ctx context.Context, _ admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				searches.Add(1)
				return InternalTestSearchCursor{
					InternalRead: func(ctx context.Context, _ uint32) ([]admodel.Object, bool, error) {
						<-ctx.Done()
						return nil, false, context.Cause(ctx)
					},
					InternalFinish: func() error {
						close(cleanupStarted)
						<-releaseCleanup
						close(cleaned)
						return nil
					},
				}, nil
			},
			InternalFinish: func() error {
				select {
				case <-cleaned:
				default:
					t.Error("session closed before active page cleanup completed")
				}
				return nil
			},
		},
	)
	t.Cleanup(func() { release(); _ = client.Close() })
	active := make(chan error, 1)
	go func() { _, err := client.Search(context.Background(), admodel.SearchOptions{}); active <- err }()
	select {
	case <-cleanupStarted:
	case <-time.After(time.Second):
		t.Fatal("active search never entered cleanup")
	}
	queued := make(chan error, 1)
	go func() { _, err := client.Search(context.Background(), admodel.SearchOptions{}); queued <- err }()
	select {
	case err := <-queued:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("queued search did not use Config.Timeout: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued search waited for the occupied gate beyond Config.Timeout")
	}
	if searches.Load() != 1 || len(adengine.InternalClientGate(client)) != 0 {
		t.Fatal("queued timeout changed active ownership or started native work")
	}
	select {
	case <-cleaned:
		t.Fatal("queued timeout released another search's cleanup")
	default:
	}
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case <-adengine.InternalClientLifetime(client).Done():
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the client")
	}
	select {
	case <-closed:
		t.Fatal("Close returned before active cleanup")
	default:
	}
	if _, err := client.Search(
		context.Background(),
		admodel.SearchOptions{},
	); !errors.Is(
		err,
		admodel.ErrClosed,
	) {
		t.Fatalf("queued search during Close: %v", err)
	}
	release()
	if err := <-active; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("active deadline was replaced: %v", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if searches.Load() != 1 {
		t.Fatal("a queued search reached the native session")
	}
}

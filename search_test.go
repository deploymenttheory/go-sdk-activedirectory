package activedirectory

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type testSearchCursor struct {
	read   func(context.Context, uint32) ([]Object, bool, error)
	finish func() error
}

func (c testSearchCursor) next(ctx context.Context, size uint32) ([]Object, bool, error) {
	return c.read(ctx, size)
}
func (c testSearchCursor) close() error { return c.finish() }

func TestSearchSelectionValidationAndAttributeState(t *testing.T) {
	for _, options := range []SearchOptions{{Scope: 3}, {PageSize: -1}, {ResultLimit: -1}, {Base: "a\x00b"}, {Filter: "(a=\x00)"}, {Properties: []string{"name)"}}, {Properties: []string{"1.1", "name"}}} {
		if options.Validate() == nil {
			t.Fatalf("accepted %#v", options)
		}
	}
	options, err := (SearchOptions{Properties: []string{"ObjectGUID", "objectguid", "description", "*"}}).normalized()
	if err != nil || !reflect.DeepEqual(options.Properties, []string{"ObjectGUID", "description", "*"}) || options.PageSize != 256 || options.Filter != "(objectClass=*)" {
		t.Fatalf("%#v %v", options, err)
	}
	object := Object{Attributes: map[string][][]byte{"objectguid": {{0, 255, 128}}, "member;range=0-1499": {[]byte("CN=first")}}, RequestedProperties: options.Properties}
	values, state := object.Attribute("OBJECTGUID")
	if state != AttributePresent || !reflect.DeepEqual(values, [][]byte{{0, 255, 128}}) {
		t.Fatal("binary attribute changed")
	}
	for name, want := range map[string]AttributeState{"description": AttributeAbsent, "canonicalName": AttributeUnloaded, "member": AttributePartial} {
		if _, got := object.Attribute(name); got != want {
			t.Fatalf("%s state %d, want %d", name, got, want)
		}
	}
}

func TestSearchCollectsThroughEmptyPagesAndHonorsLimits(t *testing.T) {
	for _, tc := range []struct {
		name     string
		counts   []int
		limit    int
		want     int
		complete bool
	}{
		{"zero", nil, 0, 0, true}, {"one", []int{1}, 0, 1, true}, {"many", []int{2, 0, 2, 1}, 0, 5, true},
		{"first", []int{1}, 1, 1, false}, {"page boundary", []int{2}, 2, 2, false}, {"within page", []int{2, 1}, 3, 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, closes := 0, 0
			cursor := testSearchCursor{read: func(_ context.Context, size uint32) ([]Object, bool, error) {
				if calls == len(tc.counts) {
					calls++
					return nil, true, nil
				}
				n := tc.counts[calls]
				calls++
				if n > int(size) {
					t.Fatalf("page request too small: %d", size)
				}
				return make([]Object, n), false, nil
			}, finish: func() error { closes++; return nil }}
			result, err := collectSearch(context.Background(), cursor, SearchOptions{PageSize: 2, ResultLimit: tc.limit, Properties: []string{"name"}})
			if err != nil || len(result.Objects) != tc.want || result.Complete != tc.complete || result.LimitReached == tc.complete || closes != 1 {
				t.Fatalf("%+v %v closes=%d", result, err, closes)
			}
			wantCalls := len(tc.counts)
			if tc.complete {
				wantCalls++
			}
			if calls != wantCalls {
				t.Fatalf("called next %d times, want %d", calls, wantCalls)
			}
			for _, object := range result.Objects {
				if _, state := object.Attribute("name"); state != AttributeAbsent {
					t.Fatal("selection lost")
				}
			}
		})
	}
}

func TestSearchPreservesPartialErrorAndCleanupFailure(t *testing.T) {
	for _, code := range []uint32{3, 4, 32, 50, 12} {
		t.Run((&LDAPError{Operation: "Search", Code: code}).Error(), func(t *testing.T) {
			cause := &LDAPError{Operation: "Search", Code: code, Diagnostic: "private server detail", MatchedDN: "DC=example"}
			cleanup := errors.New("injected cleanup failure")
			client := newClient(Config{Timeout: time.Second}, testSession{search: func(context.Context, SearchOptions) (searchCursor, error) {
				return testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) {
					return []Object{{DistinguishedName: "CN=partial"}}, false, cause
				}, finish: func() error { return cleanup }}, nil
			}, finish: func() error { return nil }})
			defer client.Close()
			result, err := client.Search(context.Background(), SearchOptions{})
			var partial *SearchError
			var native *LDAPError
			if !errors.As(err, &partial) || partial.Returned != 1 || !errors.As(err, &native) || native != cause || !errors.Is(err, cleanup) || !errors.Is(err, ErrIncompleteResult) || result.Complete {
				t.Fatalf("%+v %v", result, err)
			}
		})
	}
}

func TestSearchCancellationBetweenPages(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls, closes := 0, 0
	result, err := collectSearch(ctx, testSearchCursor{read: func(context.Context, uint32) ([]Object, bool, error) {
		calls++
		cancel()
		return []Object{{DistinguishedName: "CN=partial"}}, false, nil
	}, finish: func() error { closes++; return nil }}, SearchOptions{PageSize: 2})
	if !errors.Is(err, context.Canceled) || len(result.Objects) != 1 || calls != 1 || closes != 1 {
		t.Fatalf("%+v %v calls=%d closes=%d", result, err, calls, closes)
	}
}

func TestCloseCancelsSearchAndWaitsForPageCleanup(t *testing.T) {
	started, cleaned := make(chan struct{}), make(chan struct{})
	client := newClient(Config{Timeout: time.Second}, testSession{search: func(context.Context, SearchOptions) (searchCursor, error) {
		return testSearchCursor{read: func(ctx context.Context, _ uint32) ([]Object, bool, error) {
			close(started)
			<-ctx.Done()
			return nil, false, context.Cause(ctx)
		}, finish: func() error { close(cleaned); return nil }}, nil
	}, finish: func() error {
		select {
		case <-cleaned:
		default:
			t.Error("unbind preceded page cleanup")
		}
		return nil
	}})
	done := make(chan error, 1)
	go func() { _, err := client.Search(context.Background(), SearchOptions{}); done <- err }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("search did not start")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrClosed) || !errors.Is(err, ErrIncompleteResult) {
		t.Fatal(err)
	}
	if _, err := client.Search(context.Background(), SearchOptions{}); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

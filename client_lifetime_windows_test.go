//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"testing"
)

// A completed read must leave the session usable. Search and RootDSE return
// ErrClosed purely from c.lifetime, so a read that cancelled the lifetime would
// make every later call on that client fail with "client is closed" while the
// native session was still perfectly good. Nothing else asserts that boundary,
// and the failure mode is indistinguishable from a caller's own Close.
func TestClientLifetimeSurvivesCompletedReads(t *testing.T) {
	for _, sequence := range []struct {
		name  string
		pages []searchWirePage
		run   func(context.Context, *Client) error
	}{
		{"repeated-search", []searchWirePage{{emptyCookie: true}, {emptyCookie: true}, {emptyCookie: true}}, func(ctx context.Context, c *Client) error {
			for range 2 {
				if _, err := c.Search(ctx, SearchOptions{Base: "DC=example", PageSize: 16}); err != nil {
					return err
				}
			}
			return nil
		}},
		{"rootdse-then-search", []searchWirePage{{baseRead: true}, {emptyCookie: true}, {emptyCookie: true}}, func(ctx context.Context, c *Client) error {
			if _, err := c.RootDSE(ctx, RootDSEOptions{}); err != nil {
				return err
			}
			_, err := c.Search(ctx, SearchOptions{Base: "DC=example", PageSize: 16})
			return err
		}},
	} {
		t.Run(sequence.name, func(t *testing.T) {
			f := newSearchWireFixture(t, sequence.pages)
			var counts searchNativeCounts
			c := searchWireClient(t, f, countedSearchAPI(&counts))
			if err := c.lifetime.Err(); err != nil {
				t.Fatalf("lifetime cancelled before any read: %v", err)
			}
			if err := sequence.run(context.Background(), c); err != nil {
				t.Fatalf("read sequence failed: %v", err)
			}
			if err := c.lifetime.Err(); err != nil {
				t.Fatalf("a completed read cancelled the client lifetime: %v", err)
			}
			// A further read must therefore still be admitted rather than
			// refused as closed. The fixture carries a spare page for it.
			if _, err := c.Search(context.Background(), SearchOptions{Base: "DC=example", PageSize: 16}); errors.Is(err, ErrClosed) {
				t.Fatal("a later read was refused as closed after completed reads")
			}
		})
	}
}

// The positive control: Close must cancel the lifetime, so the assertions above
// are testing a real boundary rather than a condition that never holds.
func TestClientCloseCancelsLifetime(t *testing.T) {
	f := newSearchWireFixture(t, []searchWirePage{{emptyCookie: true}})
	var counts searchNativeCounts
	c := searchWireClient(t, f, countedSearchAPI(&counts))
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(c.lifetime.Err(), context.Canceled) {
		t.Fatalf("Close did not cancel the lifetime: %v", c.lifetime.Err())
	}
	if !errors.Is(context.Cause(c.lifetime), ErrClosed) {
		t.Fatalf("Close did not record ErrClosed as the cause: %v", context.Cause(c.lifetime))
	}
	if _, err := c.Search(context.Background(), SearchOptions{Base: "DC=example"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("a read after Close was not refused as closed: %v", err)
	}
}

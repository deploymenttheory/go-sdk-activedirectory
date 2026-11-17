//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"errors"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// A completed read must leave the session usable. Search and RootDSE return
// ErrClosed purely from c.lifetime, so a read that cancelled the lifetime would
// make every later call on that client fail with "client is closed" while the
// native session was still perfectly good. Nothing else asserts that boundary,
// and the failure mode is indistinguishable from a caller's own Close.
func TestClientLifetimeSurvivesCompletedReads(t *testing.T) {
	for _, sequence := range []struct {
		InternalName  string
		InternalPages []InternalSearchWirePage
		InternalRun   func(context.Context, *adengine.Client) error
	}{
		{"repeated-search", []InternalSearchWirePage{{InternalEmptyCookie: true}, {InternalEmptyCookie: true}, {InternalEmptyCookie: true}}, func(ctx context.Context, c *adengine.Client) error {
			for range 2 {
				if _, err := c.Search(ctx, admodel.SearchOptions{Base: "DC=example", PageSize: 16}); err != nil {
					return err
				}
			}
			return nil
		}},
		{"rootdse-then-search", []InternalSearchWirePage{{InternalBaseRead: true}, {InternalEmptyCookie: true}, {InternalEmptyCookie: true}}, func(ctx context.Context, c *adengine.Client) error {
			if _, err := c.RootDSE(ctx, admodel.RootDSEOptions{}); err != nil {
				return err
			}
			_, err := c.Search(ctx, admodel.SearchOptions{Base: "DC=example", PageSize: 16})
			return err
		}},
	} {
		t.Run(sequence.InternalName, func(t *testing.T) {
			f := InternalNewSearchWireFixture(t, sequence.InternalPages)
			var counts InternalSearchNativeCounts
			c := InternalSearchWireClient(t, f, InternalCountedSearchAPI(&counts))
			if err := adengine.InternalClientLifetime(c).Err(); err != nil {
				t.Fatalf("lifetime cancelled before any read: %v", err)
			}
			if err := sequence.InternalRun(context.Background(), c); err != nil {
				t.Fatalf("read sequence failed: %v", err)
			}
			if err := adengine.InternalClientLifetime(c).Err(); err != nil {
				t.Fatalf("a completed read cancelled the client lifetime: %v", err)
			}
			// A further read must therefore still be admitted rather than
			// refused as closed. The fixture carries a spare page for it.
			if _, err := c.Search(
				context.Background(),
				admodel.SearchOptions{Base: "DC=example", PageSize: 16},
			); errors.Is(
				err,
				admodel.ErrClosed,
			) {
				t.Fatal("a later read was refused as closed after completed reads")
			}
		})
	}
}

// The positive control: Close must cancel the lifetime, so the assertions above
// are testing a real boundary rather than a condition that never holds.
func TestClientCloseCancelsLifetime(t *testing.T) {
	f := InternalNewSearchWireFixture(t, []InternalSearchWirePage{{InternalEmptyCookie: true}})
	var counts InternalSearchNativeCounts
	c := InternalSearchWireClient(t, f, InternalCountedSearchAPI(&counts))
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(adengine.InternalClientLifetime(c).Err(), context.Canceled) {
		t.Fatalf("Close did not cancel the lifetime: %v", adengine.InternalClientLifetime(c).Err())
	}
	if !errors.Is(context.Cause(adengine.InternalClientLifetime(c)), admodel.ErrClosed) {
		t.Fatalf(
			"Close did not record ErrClosed as the cause: %v",
			context.Cause(adengine.InternalClientLifetime(c)),
		)
	}
	if _, err := c.Search(
		context.Background(),
		admodel.SearchOptions{Base: "DC=example"},
	); !errors.Is(
		err,
		admodel.ErrClosed,
	) {
		t.Fatalf("a read after Close was not refused as closed: %v", err)
	}
}

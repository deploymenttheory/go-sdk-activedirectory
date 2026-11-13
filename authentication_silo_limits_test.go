package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// A deterministic cancellation source exercises work inside a returned batch,
// without relying on scheduler timing or adding production test callbacks.
type siloWorkCancellation struct {
	context.Context
	checks, cancelAt int
}

func (c *siloWorkCancellation) Err() error {
	c.checks++
	if c.checks >= c.cancelAt {
		return context.Canceled
	}
	return nil
}

func TestAuthenticationSiloRangeAndByteBudgets(t *testing.T) {
	for _, mode := range []string{"ranges", "bytes"} {
		t.Run(mode, func(t *testing.T) {
			f := newAuthenticationSiloFixture()
			object := f.objects[siloTestDN]
			var payload []byte
			if mode == "bytes" {
				payload = make([]byte, 7<<20)
			}
			f.rangeRead = func(context.Context, string, []string) (map[string][][]byte, error) {
				attrs := authTestProjection(object.Attributes, []string{"objectGUID", "uSNChanged"})
				index := f.ranges - 1
				attrs[fmt.Sprintf("%s;range=%d-%d", siloMembersAttribute, index, index)] = [][]byte{[]byte(fmt.Sprintf("CN=Member%d,DC=example", index))}
				if payload != nil {
					attrs["extraRawResponse"] = [][]byte{payload}
				}
				return attrs, nil
			}
			result, err := readAuthenticationSiloLinks(context.Background(), f, object, siloMembersAttribute, 1048576)
			if !errors.Is(err, ErrIncompleteResult) || !result.LimitReached || result.Complete {
				t.Fatal(result, err)
			}
			if mode == "ranges" {
				if f.ranges != authenticationSiloMaxRanges || len(result.Observations) != authenticationSiloMaxRanges || len(result.DistinguishedNames) != authenticationSiloMaxRanges {
					t.Fatal(f.ranges, len(result.Observations), len(result.DistinguishedNames))
				}
			} else {
				// Nine 7-MiB responses fit; the tenth is retained but not parsed.
				if f.ranges != 10 || len(result.Observations) != 10 || len(result.DistinguishedNames) != 9 || len(result.Observations[9].Attributes["extraRawResponse"][0]) != len(payload) {
					t.Fatal(f.ranges, len(result.Observations), len(result.DistinguishedNames))
				}
			}
		})
	}
}

func TestAuthenticationSiloCanceledLargeBatchRetainsRaw(t *testing.T) {
	const count = 10000
	for _, phase := range []string{"charging", "materializing"} {
		t.Run(phase, func(t *testing.T) {
			f := newAuthenticationSiloFixture()
			object := f.objects[siloTestDN]
			values := make([][]byte, count)
			for i := range values {
				values[i] = []byte(fmt.Sprintf("CN=Member%d,DC=example", i))
			}
			f.rangeRead = func(context.Context, string, []string) (map[string][][]byte, error) {
				attrs := authTestProjection(object.Attributes, []string{"objectGUID", "uSNChanged"})
				attrs[siloMembersAttribute+";range=0-*"] = values
				return attrs, nil
			}
			ctx := &siloWorkCancellation{Context: context.Background(), cancelAt: 20}
			if phase == "materializing" {
				// Charge every value, then cancel after some DNs have been parsed.
				ctx.cancelAt = count + 200
			}
			result, err := readAuthenticationSiloLinks(ctx, f, object, siloMembersAttribute, count)
			if !errors.Is(err, context.Canceled) || result.Complete || result.LimitReached || f.ranges != 1 || len(result.Observations) != 1 || len(result.Observations[0].Attributes[siloMembersAttribute+";range=0-*"]) != count {
				t.Fatal(err, result.Complete, result.LimitReached, f.ranges, len(result.Observations))
			}
			if phase == "charging" && len(result.DistinguishedNames) != 0 {
				t.Fatal("parsed before charging finished")
			}
			if phase == "materializing" && (len(result.DistinguishedNames) == 0 || len(result.DistinguishedNames) >= count) {
				t.Fatal("cancellation did not interrupt materialization", len(result.DistinguishedNames))
			}
		})
	}
}

func TestAuthenticationSiloGrantLookupCancellation(t *testing.T) {
	links := AuthenticationSiloLinks{DistinguishedNames: make([]string, 10000)}
	for i := range links.DistinguishedNames {
		links.DistinguishedNames[i] = fmt.Sprintf("CN=Member%d,DC=example", i)
	}
	ctx := &siloWorkCancellation{Context: context.Background(), cancelAt: 20}
	present, err := authenticationSiloContains(ctx, links, "CN=Member9999,DC=example")
	if !errors.Is(err, context.Canceled) || present {
		t.Fatal(present, err)
	}
	positive, err := authenticationSiloContains(context.Background(), links, "cn=member0,dc=example")
	if err != nil || !positive {
		t.Fatal(positive, err)
	}
}

package acceptance

import (
	"context"
	"errors"
	"fmt"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// A deterministic cancellation source exercises work inside a returned batch,
// without relying on scheduler timing or adding production test callbacks.
type InternalSiloWorkCancellation struct {
	context.Context
	InternalChecks, InternalCancelAt int
}

func (c *InternalSiloWorkCancellation) Err() error {
	c.InternalChecks++
	if c.InternalChecks >= c.InternalCancelAt {
		return context.Canceled
	}
	return nil
}

func TestAuthenticationSiloRangeAndByteBudgets(t *testing.T) {
	for _, mode := range []string{"ranges", "bytes"} {
		t.Run(mode, func(t *testing.T) {
			f := InternalNewAuthenticationSiloFixture()
			object := f.InternalObjects[InternalSiloTestDN]
			var payload []byte
			if mode == "bytes" {
				payload = make([]byte, 7<<20)
			}
			f.InternalRangeRead = func(context.Context, string, []string) (map[string][][]byte, error) {
				attrs := InternalAuthTestProjection(
					object.Attributes,
					[]string{"objectGUID", "uSNChanged"},
				)
				index := f.InternalRanges - 1
				attrs[fmt.Sprintf("%s;range=%d-%d", admodel.InternalSiloMembersAttribute, index, index)] = [][]byte{
					[]byte(fmt.Sprintf("CN=Member%d,DC=example", index)),
				}
				if payload != nil {
					attrs["extraRawResponse"] = [][]byte{payload}
				}
				return attrs, nil
			}
			result, err := admodel.InternalReadAuthenticationSiloLinks(
				context.Background(),
				f,
				object,
				admodel.InternalSiloMembersAttribute,
				1048576,
			)
			if !errors.Is(err, admodel.ErrIncompleteResult) || !result.LimitReached ||
				result.Complete {
				t.Fatal(result, err)
			}
			if mode == "ranges" {
				if f.InternalRanges != admodel.InternalAuthenticationSiloMaxRanges ||
					len(result.Observations) != admodel.InternalAuthenticationSiloMaxRanges ||
					len(result.DistinguishedNames) != admodel.InternalAuthenticationSiloMaxRanges {
					t.Fatal(
						f.InternalRanges,
						len(result.Observations),
						len(result.DistinguishedNames),
					)
				}
			} else {
				// Nine 7-MiB responses fit; the tenth is retained but not parsed.
				if f.InternalRanges != 10 || len(result.Observations) != 10 ||
					len(result.DistinguishedNames) != 9 ||
					len(result.Observations[9].Attributes["extraRawResponse"][0]) != len(payload) {
					t.Fatal(
						f.InternalRanges,
						len(result.Observations),
						len(result.DistinguishedNames),
					)
				}
			}
		})
	}
}

func TestAuthenticationSiloCanceledLargeBatchRetainsRaw(t *testing.T) {
	const count = 10000
	for _, phase := range []string{"charging", "materializing"} {
		t.Run(phase, func(t *testing.T) {
			f := InternalNewAuthenticationSiloFixture()
			object := f.InternalObjects[InternalSiloTestDN]
			values := make([][]byte, count)
			for i := range values {
				values[i] = []byte(fmt.Sprintf("CN=Member%d,DC=example", i))
			}
			f.InternalRangeRead = func(context.Context, string, []string) (map[string][][]byte, error) {
				attrs := InternalAuthTestProjection(
					object.Attributes,
					[]string{"objectGUID", "uSNChanged"},
				)
				attrs[admodel.InternalSiloMembersAttribute+";range=0-*"] = values
				return attrs, nil
			}
			ctx := &InternalSiloWorkCancellation{
				Context:          context.Background(),
				InternalCancelAt: 20,
			}
			if phase == "materializing" {
				// Charge every value, then cancel after some DNs have been parsed.
				ctx.InternalCancelAt = count + 200
			}
			result, err := admodel.InternalReadAuthenticationSiloLinks(
				ctx,
				f,
				object,
				admodel.InternalSiloMembersAttribute,
				count,
			)
			if !errors.Is(err, context.Canceled) || result.Complete || result.LimitReached ||
				f.InternalRanges != 1 ||
				len(result.Observations) != 1 ||
				len(
					result.Observations[0].Attributes[admodel.InternalSiloMembersAttribute+";range=0-*"],
				) != count {
				t.Fatal(
					err,
					result.Complete,
					result.LimitReached,
					f.InternalRanges,
					len(result.Observations),
				)
			}
			if phase == "charging" && len(result.DistinguishedNames) != 0 {
				t.Fatal("parsed before charging finished")
			}
			if phase == "materializing" &&
				(len(result.DistinguishedNames) == 0 || len(result.DistinguishedNames) >= count) {
				t.Fatal(
					"cancellation did not interrupt materialization",
					len(result.DistinguishedNames),
				)
			}
		})
	}
}

func TestAuthenticationSiloGrantLookupCancellation(t *testing.T) {
	links := admodel.AuthenticationSiloLinks{DistinguishedNames: make([]string, 10000)}
	for i := range links.DistinguishedNames {
		links.DistinguishedNames[i] = fmt.Sprintf("CN=Member%d,DC=example", i)
	}
	ctx := &InternalSiloWorkCancellation{Context: context.Background(), InternalCancelAt: 20}
	present, err := admodel.InternalAuthenticationSiloContains(
		ctx,
		links,
		"CN=Member9999,DC=example",
	)
	if !errors.Is(err, context.Canceled) || present {
		t.Fatal(present, err)
	}
	positive, err := admodel.InternalAuthenticationSiloContains(
		context.Background(),
		links,
		"cn=member0,dc=example",
	)
	if err != nil || !positive {
		t.Fatal(positive, err)
	}
}

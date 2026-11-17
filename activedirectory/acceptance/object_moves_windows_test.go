//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type InternalMoveWireSession struct {
	*InternalMoveTestSession
	InternalNative *adengine.InternalLdapSession
	InternalCalls  int
}

func (s *InternalMoveWireSession) InternalLdapWrite(
	ctx context.Context,
	request admodel.InternalLdapWriteRequest,
) admodel.InternalLdapWriteAttempt {
	s.InternalCalls++
	attempt := s.InternalNative.InternalLdapWrite(ctx, request)
	if attempt.State == admodel.InternalLdapWriteAccepted {
		_ = s.InternalMoveTestSession.InternalLdapWrite(ctx, request)
	}
	return attempt
}

func TestNativeMoveObjectParentAndCrossDomainControlWire(t *testing.T) {
	for _, kind := range []string{"DS", "LDS", "cross-user", "cross-computer"} {
		for _, code := range []byte{0, 32, 50, 53, 66, 68, 80, 122} {
			t.Run(fmt.Sprintf("%s/%d", kind, code), func(t *testing.T) {
				cross := kind == "cross-user" || kind == "cross-computer"
				f := InternalNewMoveTestFixture(t, cross, kind == "LDS")
				if kind == "cross-computer" {
					o := f.InternalSrc.InternalObjects[InternalMoveTestSourceDN]
					o.Attributes["objectclass"] = append(
						o.Attributes["objectclass"],
						[]byte("computer"),
					)
					o.Attributes["useraccountcontrol"] = [][]byte{[]byte("4096")}
					f.InternalSrc.InternalObjects[InternalMoveTestSourceDN] = o
				}
				guid, _ := admodel.GUIDFromBytes(
					f.InternalSrc.InternalObjects[InternalMoveTestSourceDN].Attributes["objectguid"][0],
				)
				version := admodel.ObjectVersion{
					Source:     adengine.InternalClientConfig(f.InternalSource).Endpoint,
					GUID:       guid,
					USNChanged: 7,
				}
				f.InternalRequest.Options.ExpectedVersion = &version
				body := append(
					InternalSearchBER(4, []byte(admodel.InternalObjectGUIDTarget(guid))),
					InternalSearchBER(4, []byte(`CN=李\, Demo`))...)
				body = append(body, 1, 1, 255)
				body = append(
					body,
					InternalSearchBER(0x80, []byte(f.InternalRequest.TargetParent.String()))...)
				controlValues := [][]byte{
					InternalSearchBER(
						0x30,
						InternalSearchBER(4, []byte(admodel.InternalObjectAssertionControl)),
						[]byte{1, 1, 255},
						InternalSearchBER(4, admodel.InternalObjectVersionAssertion(version)),
					),
				}
				if cross {
					controlValues = append(
						controlValues,
						InternalSearchBER(
							0x30,
							InternalSearchBER(
								4,
								[]byte(admodel.InternalObjectCrossDomainMoveControl),
							),
							[]byte{1, 1, 255},
							InternalSearchBER(4, []byte("dst.child.example")),
						),
					)
				}
				fixture := InternalNewWriteWireFixture(
					t,
					0x6c,
					0x6d,
					body,
					InternalSearchBER(0xa0, controlValues...),
					code,
				)
				var counts InternalSearchNativeCounts
				wire := InternalSearchWireClient(
					t,
					&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
					InternalCountedSearchAPI(&counts),
				)
				session := &InternalMoveWireSession{
					InternalMoveTestSession: f.InternalSrc,
					InternalNative:          (*adengine.InternalClientSessionPointer(wire)).(*adengine.InternalLdapSession),
				}
				(*adengine.InternalClientSessionPointer(f.InternalSource)) = session
				result, err := f.InternalSource.MoveObject(context.Background(), f.InternalRequest)
				if session.InternalCalls != 1 {
					t.Fatal("write was omitted or replayed", session.InternalCalls)
				}
				if code == 0 {
					if err != nil || !result.Mutation.Verified ||
						result.Mutation.State != admodel.ObjectWriteAccepted {
						t.Fatal(result.Mutation.State, err)
					}
				} else {
					var native *admodel.LDAPError
					if !errors.As(err, &native) || native.Code != uint32(code) ||
						native.Diagnostic != "private wire diagnostic" ||
						result.Mutation.State != admodel.ObjectWriteRejected ||
						result.Mutation.Verified {
						t.Fatal(result.Mutation.State, err)
					}
				}
				if result.Mutation.PartialEffectsPossible != cross {
					t.Fatal("partial-effects distinction", result.Mutation.PartialEffectsPossible)
				}
				if err := wire.Close(); err != nil {
					t.Fatal(err)
				}
				if counts != (InternalSearchNativeCounts{}) {
					t.Fatal("native owners", counts)
				}
			})
		}
	}
}

func TestNativeCrossDomainMoveCancellationNeverReplays(t *testing.T) {
	f := InternalNewMoveTestFixture(t, true, false)
	guid, _ := admodel.GUIDFromBytes(
		f.InternalSrc.InternalObjects[InternalMoveTestSourceDN].Attributes["objectguid"][0],
	)
	body := append(
		InternalSearchBER(4, []byte(admodel.InternalObjectGUIDTarget(guid))),
		InternalSearchBER(4, []byte(`CN=李\, Demo`))...)
	body = append(body, 1, 1, 255)
	body = append(body, InternalSearchBER(0x80, []byte(f.InternalRequest.TargetParent.String()))...)
	controls := InternalSearchBER(
		0xa0,
		InternalSearchBER(
			0x30,
			InternalSearchBER(4, []byte(admodel.InternalObjectCrossDomainMoveControl)),
			[]byte{1, 1, 255},
			InternalSearchBER(4, []byte("dst.child.example")),
		),
	)
	fixture := InternalNewWriteWireFixture(t, 0x6c, 0x6d, body, controls, 255)
	var counts InternalSearchNativeCounts
	wire := InternalSearchWireClient(
		t,
		&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
		InternalCountedSearchAPI(&counts),
	)
	session := &InternalMoveWireSession{
		InternalMoveTestSession: f.InternalSrc,
		InternalNative:          (*adengine.InternalClientSessionPointer(wire)).(*adengine.InternalLdapSession),
	}
	(*adengine.InternalClientSessionPointer(f.InternalSource)) = session
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-fixture.InternalSubmitted:
			cancel()
		case <-ctx.Done():
		}
	}()
	result, err := f.InternalSource.MoveObject(ctx, f.InternalRequest)
	if session.InternalCalls != 1 || !errors.Is(err, admodel.ErrObjectWriteUncertain) ||
		result.Mutation.State != admodel.ObjectWriteUncertain ||
		!result.Mutation.PartialEffectsPossible ||
		result.Mutation.After != nil ||
		len(f.InternalWrites) != 0 {
		t.Fatal(result.Mutation.State, err, session.InternalCalls)
	}
	if err := wire.Close(); err != nil {
		t.Fatal(err)
	}
	if counts != (InternalSearchNativeCounts{}) {
		t.Fatal(counts)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation watcher stuck")
	}
}

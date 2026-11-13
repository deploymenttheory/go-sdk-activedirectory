//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

type moveWireSession struct {
	*moveTestSession
	native *ldapSession
	calls  int
}

func (s *moveWireSession) ldapWrite(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
	s.calls++
	attempt := s.native.ldapWrite(ctx, request)
	if attempt.State == ldapWriteAccepted {
		_ = s.moveTestSession.ldapWrite(ctx, request)
	}
	return attempt
}

func TestNativeMoveObjectParentAndCrossDomainControlWire(t *testing.T) {
	for _, kind := range []string{"DS", "LDS", "cross-user", "cross-computer"} {
		for _, code := range []byte{0, 32, 50, 53, 66, 68, 80, 122} {
			t.Run(fmt.Sprintf("%s/%d", kind, code), func(t *testing.T) {
				cross := kind == "cross-user" || kind == "cross-computer"
				f := newMoveTestFixture(t, cross, kind == "LDS")
				if kind == "cross-computer" {
					o := f.src.objects[moveTestSourceDN]
					o.Attributes["objectclass"] = append(o.Attributes["objectclass"], []byte("computer"))
					o.Attributes["useraccountcontrol"] = [][]byte{[]byte("4096")}
					f.src.objects[moveTestSourceDN] = o
				}
				guid, _ := GUIDFromBytes(f.src.objects[moveTestSourceDN].Attributes["objectguid"][0])
				version := ObjectVersion{Source: f.source.config.Endpoint, GUID: guid, USNChanged: 7}
				f.request.Options.ExpectedVersion = &version
				body := append(searchBER(4, []byte(objectGUIDTarget(guid))), searchBER(4, []byte(`CN=李\, Demo`))...)
				body = append(body, 1, 1, 255)
				body = append(body, searchBER(0x80, []byte(f.request.TargetParent.String()))...)
				controlValues := [][]byte{searchBER(0x30, searchBER(4, []byte(objectAssertionControl)), []byte{1, 1, 255}, searchBER(4, objectVersionAssertion(version)))}
				if cross {
					controlValues = append(controlValues, searchBER(0x30, searchBER(4, []byte(objectCrossDomainMoveControl)), []byte{1, 1, 255}, searchBER(4, []byte("dst.child.example"))))
				}
				fixture := newWriteWireFixture(t, 0x6c, 0x6d, body, searchBER(0xa0, controlValues...), code)
				var counts searchNativeCounts
				wire := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&counts))
				session := &moveWireSession{moveTestSession: f.src, native: wire.session.(*ldapSession)}
				f.source.session = session
				result, err := f.source.MoveObject(context.Background(), f.request)
				if session.calls != 1 {
					t.Fatal("write was omitted or replayed", session.calls)
				}
				if code == 0 {
					if err != nil || !result.Mutation.Verified || result.Mutation.State != ObjectWriteAccepted {
						t.Fatal(result.Mutation.State, err)
					}
				} else {
					var native *LDAPError
					if !errors.As(err, &native) || native.Code != uint32(code) || native.Diagnostic != "private wire diagnostic" || result.Mutation.State != ObjectWriteRejected || result.Mutation.Verified {
						t.Fatal(result.Mutation.State, err)
					}
				}
				if result.Mutation.PartialEffectsPossible != cross {
					t.Fatal("partial-effects distinction", result.Mutation.PartialEffectsPossible)
				}
				if err := wire.Close(); err != nil {
					t.Fatal(err)
				}
				if counts != (searchNativeCounts{}) {
					t.Fatal("native owners", counts)
				}
			})
		}
	}
}

func TestNativeCrossDomainMoveCancellationNeverReplays(t *testing.T) {
	f := newMoveTestFixture(t, true, false)
	guid, _ := GUIDFromBytes(f.src.objects[moveTestSourceDN].Attributes["objectguid"][0])
	body := append(searchBER(4, []byte(objectGUIDTarget(guid))), searchBER(4, []byte(`CN=李\, Demo`))...)
	body = append(body, 1, 1, 255)
	body = append(body, searchBER(0x80, []byte(f.request.TargetParent.String()))...)
	controls := searchBER(0xa0, searchBER(0x30, searchBER(4, []byte(objectCrossDomainMoveControl)), []byte{1, 1, 255}, searchBER(4, []byte("dst.child.example"))))
	fixture := newWriteWireFixture(t, 0x6c, 0x6d, body, controls, 255)
	var counts searchNativeCounts
	wire := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&counts))
	session := &moveWireSession{moveTestSession: f.src, native: wire.session.(*ldapSession)}
	f.source.session = session
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-fixture.submitted:
			cancel()
		case <-ctx.Done():
		}
	}()
	result, err := f.source.MoveObject(ctx, f.request)
	if session.calls != 1 || !errors.Is(err, ErrObjectWriteUncertain) || result.Mutation.State != ObjectWriteUncertain || !result.Mutation.PartialEffectsPossible || result.Mutation.After != nil || len(f.writes) != 0 {
		t.Fatal(result.Mutation.State, err, session.calls)
	}
	if err := wire.Close(); err != nil {
		t.Fatal(err)
	}
	if counts != (searchNativeCounts{}) {
		t.Fatal(counts)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation watcher stuck")
	}
}

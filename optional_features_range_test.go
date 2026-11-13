package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

type optionalFeatureRangeSession struct {
	optionalFeatureTestSession
	rangeRead func(context.Context, string, []string) (map[string][][]byte, error)
}

func TestOptionalFeatureRangeReadBoundStopsEndlessServer(t *testing.T) {
	objects, feature := optionalFeatureFixture()
	client := optionalFeatureFixtureClient(t, objects, &feature, nil)
	client.config.Timeout = 5 * time.Second
	calls := 0
	client.session = optionalFeatureRangeSession{optionalFeatureTestSession: client.session.(optionalFeatureTestSession), rangeRead: func(context.Context, string, []string) (map[string][][]byte, error) {
		i := calls
		calls++
		return optionalScopeRangeObject(fmt.Sprintf("msds-enabledfeaturebl;range=%d-%d", i, i), fmt.Sprintf("CN=Scope%d", i)), nil
	}}
	result, err := client.OptionalFeatures(context.Background(), OptionalFeatureQuery{})
	if !errors.Is(err, ErrIncompleteResult) || result.Complete || calls != optionalFeatureMaxScopeReads || len(result.Features[0].EnabledScopes) != calls || len(result.Features[0].EnabledScopeObjects) != calls {
		t.Fatalf("read bound: calls=%d complete=%v err=%v", calls, result.Complete, err)
	}
}

func TestOptionalFeatureCloseCancelsActiveContinuation(t *testing.T) {
	objects, feature := optionalFeatureFixture()
	client := optionalFeatureFixtureClient(t, objects, &feature, nil)
	active := make(chan struct{})
	finished := make(chan struct{})
	calls := 0
	client.session = optionalFeatureRangeSession{optionalFeatureTestSession: client.session.(optionalFeatureTestSession), rangeRead: func(ctx context.Context, _ string, _ []string) (map[string][][]byte, error) {
		calls++
		if calls == 1 {
			return optionalScopeRangeObject("msds-enabledfeaturebl;range=0-0", "CN=Scope0"), nil
		}
		close(active)
		<-ctx.Done()
		return nil, context.Cause(ctx)
	}}
	go func() {
		defer close(finished)
		result, err := client.OptionalFeatures(context.Background(), OptionalFeatureQuery{})
		if !errors.Is(err, ErrClosed) || result.Complete || len(result.Features) != 1 || len(result.Features[0].EnabledScopes) != 1 {
			t.Errorf("close lost partial result: %+v err=%v", result, err)
		}
	}()
	select {
	case <-active:
	case <-time.After(2 * time.Second):
		t.Fatal("continuation did not begin")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("close did not finish active continuation")
	}
	if calls != 2 {
		t.Fatal("continued after Close", calls)
	}
}

func (s optionalFeatureRangeSession) rangedBaseObject(ctx context.Context, dn string, attrs []string) (map[string][][]byte, error) {
	return s.rangeRead(ctx, dn, attrs)
}

func optionalScopeRangeObject(name string, values ...string) map[string][][]byte {
	guid, _ := optionalFeatureGUIDBytes(optionalTestGUID)
	attrs := map[string][][]byte{"distinguishedname": {[]byte(optionalTestDN)}, "objectguid": {guid}}
	if name != "" {
		attrs[name] = [][]byte{}
		for _, value := range values {
			attrs[name] = append(attrs[name], []byte(value))
		}
	}
	return attrs
}

func TestOptionalFeatureEnabledScopesContinueToTerminal(t *testing.T) {
	objects, feature := optionalFeatureFixture()
	client := optionalFeatureFixtureClient(t, objects, &feature, nil)
	first := optionalScopeRangeObject("msds-enabledfeaturebl;range=0-1", "CN=Scope0", "CN=Scope1")
	first["msds-enabledfeaturebl"] = [][]byte{} // documented empty plain placeholder
	pages := []map[string][][]byte{first, optionalScopeRangeObject("msds-enabledfeaturebl;range=2-*", "CN=Scope2")}
	calls := 0
	client.session = optionalFeatureRangeSession{optionalFeatureTestSession: client.session.(optionalFeatureTestSession), rangeRead: func(_ context.Context, dn string, attrs []string) (map[string][][]byte, error) {
		if dn != optionalTestDN || calls >= len(pages) {
			t.Fatal("unexpected range target/replay", dn, calls)
		}
		want := "msDS-EnabledFeatureBL"
		if calls == 1 {
			want = "msDS-EnabledFeatureBL;range=2-*"
		}
		if attrs[0] != want {
			t.Fatalf("requested %v, want %s", attrs, want)
		}
		page := pages[calls]
		calls++
		return page, nil
	}}
	result, err := client.OptionalFeatures(context.Background(), OptionalFeatureQuery{})
	if err != nil || !result.Complete || calls != 2 || len(result.Features) != 1 {
		t.Fatalf("result=%+v calls=%d err=%v", result, calls, err)
	}
	got := result.Features[0]
	if got.EnabledScopesState != AttributePresent || !reflect.DeepEqual(got.EnabledScopes, []string{"CN=Scope0", "CN=Scope1", "CN=Scope2"}) || len(got.EnabledScopeObjects) != 2 {
		t.Fatalf("missing complete/raw scope sequence: %+v", got)
	}
	if len(got.EnabledScopeObjects[0].Attributes["msds-enabledfeaturebl;range=0-1"]) != 2 || len(got.EnabledScopeObjects[1].Attributes["msds-enabledfeaturebl;range=2-*"]) != 1 {
		t.Fatal("raw range labels/values changed")
	}
}

func TestOptionalFeatureRangeErrorsRetainValidatedPrefix(t *testing.T) {
	for _, mode := range []string{"gap", "reset", "short", "duplicate-value", "duplicate-descriptions", "mixed-plain", "missing", "native-failure", "canceled", "identity-changed", "terminal-empty", "nondecimal"} {
		t.Run(mode, func(t *testing.T) {
			objects, feature := optionalFeatureFixture()
			client := optionalFeatureFixtureClient(t, objects, &feature, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			native := &LDAPError{Code: 50, Diagnostic: "private range failure"}
			calls := 0
			second := optionalScopeRangeObject("msds-enabledfeaturebl;range=1-*", "CN=Scope1")
			switch mode {
			case "gap":
				second = optionalScopeRangeObject("msds-enabledfeaturebl;range=2-*", "CN=Scope2")
			case "reset":
				second = optionalScopeRangeObject("msds-enabledfeaturebl;range=0-*", "CN=Scope0")
			case "short":
				second = optionalScopeRangeObject("msds-enabledfeaturebl;range=1-3", "CN=Scope1")
			case "duplicate-value":
				second = optionalScopeRangeObject("msds-enabledfeaturebl;range=1-*", "cn=scope0")
			case "duplicate-descriptions":
				second["MSDS-EnabledFeatureBL;range=1-*"] = [][]byte{[]byte("CN=other")}
			case "mixed-plain":
				second["msds-enabledfeaturebl"] = [][]byte{[]byte("CN=other")}
			case "missing":
				second = optionalScopeRangeObject("")
			case "identity-changed":
				second["objectguid"] = [][]byte{make([]byte, 16)}
			case "terminal-empty":
				second = optionalScopeRangeObject("msds-enabledfeaturebl;range=1-*")
			case "nondecimal":
				second = optionalScopeRangeObject("msds-enabledfeaturebl;range=+1-*", "CN=Scope1")
			}
			client.session = optionalFeatureRangeSession{optionalFeatureTestSession: client.session.(optionalFeatureTestSession), rangeRead: func(_ context.Context, _ string, _ []string) (map[string][][]byte, error) {
				calls++
				if calls == 1 {
					if mode == "canceled" {
						cancel()
					}
					return optionalScopeRangeObject("msds-enabledfeaturebl;range=0-0", "CN=Scope0"), nil
				}
				if calls != 2 {
					t.Fatal("range error replayed", calls)
				}
				if mode == "native-failure" {
					return second, native
				}
				return second, nil
			}}
			result, err := client.OptionalFeatures(ctx, OptionalFeatureQuery{})
			if err == nil || result.Complete || len(result.Features) != 1 {
				t.Fatalf("accepted broken sequence: %+v err=%v", result, err)
			}
			got := result.Features[0]
			if got.EnabledScopesState != AttributePartial || len(got.EnabledScopes) == 0 || got.EnabledScopes[0] != "CN=Scope0" {
				t.Fatalf("validated prefix lost: %+v err=%v", got, err)
			}
			if mode == "canceled" {
				if calls != 1 || !errors.Is(err, context.Canceled) {
					t.Fatal(calls, err)
				}
			} else if calls != 2 || len(got.EnabledScopeObjects) != 2 {
				t.Fatal("raw failing observation lost", calls, got)
			}
			if mode == "native-failure" && (!errors.Is(err, native) || strings.Contains(err.Error(), "private")) {
				t.Fatal("native error/diagnostic handling", err)
			}
		})
	}
}

func TestOptionalFeatureRangeAbsentEmptyAndTerminalStates(t *testing.T) {
	for _, mode := range []string{"absent", "plain-empty", "terminal", "initial-duplicate", "initial-denied"} {
		t.Run(mode, func(t *testing.T) {
			objects, feature := optionalFeatureFixture()
			client := optionalFeatureFixtureClient(t, objects, &feature, nil)
			attrs := optionalScopeRangeObject("")
			var readErr error
			switch mode {
			case "plain-empty":
				attrs = optionalScopeRangeObject("msds-enabledfeaturebl")
			case "terminal":
				attrs = optionalScopeRangeObject("msds-enabledfeaturebl;range=0-*", "CN=Scope0")
			case "initial-duplicate":
				attrs = optionalScopeRangeObject("msds-enabledfeaturebl;range=0-*", "CN=Scope0", "cn=scope0")
			case "initial-denied":
				readErr = &LDAPError{Code: 50}
			}
			client.session = optionalFeatureRangeSession{optionalFeatureTestSession: client.session.(optionalFeatureTestSession), rangeRead: func(context.Context, string, []string) (map[string][][]byte, error) { return attrs, readErr }}
			result, err := client.OptionalFeatures(context.Background(), OptionalFeatureQuery{})
			got := result.Features[0]
			if mode == "initial-denied" || mode == "initial-duplicate" {
				if err == nil || result.Complete || got.EnabledScopesState != AttributePartial {
					t.Fatal(result, err)
				}
				return
			}
			if err != nil || !result.Complete {
				t.Fatal(result, err)
			}
			want := AttributePresent
			if mode == "absent" {
				want = AttributeAbsent
			}
			if got.EnabledScopesState != want || len(got.EnabledScopeObjects) != 1 {
				t.Fatal(got)
			}
		})
	}
}

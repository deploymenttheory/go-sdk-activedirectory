package acceptance

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_directory_settings "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/directory_settings"
)

type InternalOptionalFeatureRangeSession struct {
	InternalOptionalFeatureTestSession
	InternalRangeRead func(context.Context, string, []string) (map[string][][]byte, error)
}

func TestOptionalFeatureRangeReadBoundStopsEndlessServer(t *testing.T) {
	objects, feature := InternalOptionalFeatureFixture()
	client := InternalOptionalFeatureFixtureClient(t, objects, &feature, nil)
	(*adengine.InternalClientConfigPointer(client)).Timeout = 5 * time.Second
	calls := 0
	(*adengine.InternalClientSessionPointer(client)) = InternalOptionalFeatureRangeSession{
		InternalOptionalFeatureTestSession: adengine.InternalClientSession(client).(InternalOptionalFeatureTestSession),
		InternalRangeRead: func(context.Context, string, []string) (map[string][][]byte, error) {
			i := calls
			calls++
			return InternalOptionalScopeRangeObject(
				fmt.Sprintf("msds-enabledfeaturebl;range=%d-%d", i, i),
				fmt.Sprintf("CN=Scope%d", i),
			), nil
		},
	}
	result, err := adservice_directory_settings.New(client).
		OptionalFeatures(context.Background(), admodel.OptionalFeatureQuery{})
	if !errors.Is(err, admodel.ErrIncompleteResult) || result.Complete ||
		calls != admodel.InternalOptionalFeatureMaxScopeReads ||
		len(result.Features[0].EnabledScopes) != calls ||
		len(result.Features[0].EnabledScopeObjects) != calls {
		t.Fatalf("read bound: calls=%d complete=%v err=%v", calls, result.Complete, err)
	}
}

func TestOptionalFeatureCloseCancelsActiveContinuation(t *testing.T) {
	objects, feature := InternalOptionalFeatureFixture()
	client := InternalOptionalFeatureFixtureClient(t, objects, &feature, nil)
	active := make(chan struct{})
	finished := make(chan struct{})
	calls := 0
	(*adengine.InternalClientSessionPointer(client)) = InternalOptionalFeatureRangeSession{
		InternalOptionalFeatureTestSession: adengine.InternalClientSession(client).(InternalOptionalFeatureTestSession),
		InternalRangeRead: func(ctx context.Context, _ string, _ []string) (map[string][][]byte, error) {
			calls++
			if calls == 1 {
				return InternalOptionalScopeRangeObject(
					"msds-enabledfeaturebl;range=0-0",
					"CN=Scope0",
				), nil
			}
			close(active)
			<-ctx.Done()
			return nil, context.Cause(ctx)
		},
	}
	go func() {
		defer close(finished)
		result, err := adservice_directory_settings.New(client).
			OptionalFeatures(context.Background(), admodel.OptionalFeatureQuery{})
		if !errors.Is(err, admodel.ErrClosed) || result.Complete || len(result.Features) != 1 ||
			len(result.Features[0].EnabledScopes) != 1 {
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

func (s InternalOptionalFeatureRangeSession) InternalRangedBaseObject(
	ctx context.Context,
	dn string,
	attrs []string,
) (map[string][][]byte, error) {
	return s.InternalRangeRead(ctx, dn, attrs)
}

func InternalOptionalScopeRangeObject(name string, values ...string) map[string][][]byte {
	guid, _ := admodel.InternalOptionalFeatureGUIDBytes(InternalOptionalTestGUID)
	attrs := map[string][][]byte{
		"distinguishedname": {[]byte(InternalOptionalTestDN)},
		"objectguid":        {guid},
	}
	if name != "" {
		attrs[name] = [][]byte{}
		for _, value := range values {
			attrs[name] = append(attrs[name], []byte(value))
		}
	}
	return attrs
}

func TestOptionalFeatureEnabledScopesContinueToTerminal(t *testing.T) {
	objects, feature := InternalOptionalFeatureFixture()
	client := InternalOptionalFeatureFixtureClient(t, objects, &feature, nil)
	first := InternalOptionalScopeRangeObject(
		"msds-enabledfeaturebl;range=0-1",
		"CN=Scope0",
		"CN=Scope1",
	)
	first["msds-enabledfeaturebl"] = [][]byte{} // documented empty plain placeholder
	pages := []map[string][][]byte{
		first,
		InternalOptionalScopeRangeObject("msds-enabledfeaturebl;range=2-*", "CN=Scope2"),
	}
	calls := 0
	(*adengine.InternalClientSessionPointer(client)) = InternalOptionalFeatureRangeSession{
		InternalOptionalFeatureTestSession: adengine.InternalClientSession(client).(InternalOptionalFeatureTestSession),
		InternalRangeRead: func(_ context.Context, dn string, attrs []string) (map[string][][]byte, error) {
			if dn != InternalOptionalTestDN || calls >= len(pages) {
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
		},
	}
	result, err := adservice_directory_settings.New(client).
		OptionalFeatures(context.Background(), admodel.OptionalFeatureQuery{})
	if err != nil || !result.Complete || calls != 2 || len(result.Features) != 1 {
		t.Fatalf("result=%+v calls=%d err=%v", result, calls, err)
	}
	got := result.Features[0]
	if got.EnabledScopesState != admodel.AttributePresent ||
		!reflect.DeepEqual(got.EnabledScopes, []string{"CN=Scope0", "CN=Scope1", "CN=Scope2"}) ||
		len(got.EnabledScopeObjects) != 2 {
		t.Fatalf("missing complete/raw scope sequence: %+v", got)
	}
	if len(got.EnabledScopeObjects[0].Attributes["msds-enabledfeaturebl;range=0-1"]) != 2 ||
		len(got.EnabledScopeObjects[1].Attributes["msds-enabledfeaturebl;range=2-*"]) != 1 {
		t.Fatal("raw range labels/values changed")
	}
}

func TestOptionalFeatureRangeErrorsRetainValidatedPrefix(t *testing.T) {
	for _, mode := range []string{"gap", "reset", "short", "duplicate-value", "duplicate-descriptions", "mixed-plain", "missing", "native-failure", "canceled", "identity-changed", "terminal-empty", "nondecimal"} {
		t.Run(mode, func(t *testing.T) {
			objects, feature := InternalOptionalFeatureFixture()
			client := InternalOptionalFeatureFixtureClient(t, objects, &feature, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			native := &admodel.LDAPError{Code: 50, Diagnostic: "private range failure"}
			calls := 0
			second := InternalOptionalScopeRangeObject(
				"msds-enabledfeaturebl;range=1-*",
				"CN=Scope1",
			)
			switch mode {
			case "gap":
				second = InternalOptionalScopeRangeObject(
					"msds-enabledfeaturebl;range=2-*",
					"CN=Scope2",
				)
			case "reset":
				second = InternalOptionalScopeRangeObject(
					"msds-enabledfeaturebl;range=0-*",
					"CN=Scope0",
				)
			case "short":
				second = InternalOptionalScopeRangeObject(
					"msds-enabledfeaturebl;range=1-3",
					"CN=Scope1",
				)
			case "duplicate-value":
				second = InternalOptionalScopeRangeObject(
					"msds-enabledfeaturebl;range=1-*",
					"cn=scope0",
				)
			case "duplicate-descriptions":
				second["MSDS-EnabledFeatureBL;range=1-*"] = [][]byte{[]byte("CN=other")}
			case "mixed-plain":
				second["msds-enabledfeaturebl"] = [][]byte{[]byte("CN=other")}
			case "missing":
				second = InternalOptionalScopeRangeObject("")
			case "identity-changed":
				second["objectguid"] = [][]byte{make([]byte, 16)}
			case "terminal-empty":
				second = InternalOptionalScopeRangeObject("msds-enabledfeaturebl;range=1-*")
			case "nondecimal":
				second = InternalOptionalScopeRangeObject(
					"msds-enabledfeaturebl;range=+1-*",
					"CN=Scope1",
				)
			}
			(*adengine.InternalClientSessionPointer(client)) = InternalOptionalFeatureRangeSession{
				InternalOptionalFeatureTestSession: adengine.InternalClientSession(client).(InternalOptionalFeatureTestSession),
				InternalRangeRead: func(_ context.Context, _ string, _ []string) (map[string][][]byte, error) {
					calls++
					if calls == 1 {
						if mode == "canceled" {
							cancel()
						}
						return InternalOptionalScopeRangeObject(
							"msds-enabledfeaturebl;range=0-0",
							"CN=Scope0",
						), nil
					}
					if calls != 2 {
						t.Fatal("range error replayed", calls)
					}
					if mode == "native-failure" {
						return second, native
					}
					return second, nil
				},
			}
			result, err := adservice_directory_settings.New(client).
				OptionalFeatures(ctx, admodel.OptionalFeatureQuery{})
			if err == nil || result.Complete || len(result.Features) != 1 {
				t.Fatalf("accepted broken sequence: %+v err=%v", result, err)
			}
			got := result.Features[0]
			if got.EnabledScopesState != admodel.AttributePartial || len(got.EnabledScopes) == 0 ||
				got.EnabledScopes[0] != "CN=Scope0" {
				t.Fatalf("validated prefix lost: %+v err=%v", got, err)
			}
			if mode == "canceled" {
				if calls != 1 || !errors.Is(err, context.Canceled) {
					t.Fatal(calls, err)
				}
			} else if calls != 2 || len(got.EnabledScopeObjects) != 2 {
				t.Fatal("raw failing observation lost", calls, got)
			}
			if mode == "native-failure" &&
				(!errors.Is(err, native) || strings.Contains(err.Error(), "private")) {
				t.Fatal("native error/diagnostic handling", err)
			}
		})
	}
}

func TestOptionalFeatureRangeAbsentEmptyAndTerminalStates(t *testing.T) {
	for _, mode := range []string{"absent", "plain-empty", "terminal", "initial-duplicate", "initial-denied"} {
		t.Run(mode, func(t *testing.T) {
			objects, feature := InternalOptionalFeatureFixture()
			client := InternalOptionalFeatureFixtureClient(t, objects, &feature, nil)
			attrs := InternalOptionalScopeRangeObject("")
			var readErr error
			switch mode {
			case "plain-empty":
				attrs = InternalOptionalScopeRangeObject("msds-enabledfeaturebl")
			case "terminal":
				attrs = InternalOptionalScopeRangeObject(
					"msds-enabledfeaturebl;range=0-*",
					"CN=Scope0",
				)
			case "initial-duplicate":
				attrs = InternalOptionalScopeRangeObject(
					"msds-enabledfeaturebl;range=0-*",
					"CN=Scope0",
					"cn=scope0",
				)
			case "initial-denied":
				readErr = &admodel.LDAPError{Code: 50}
			}
			(*adengine.InternalClientSessionPointer(client)) = InternalOptionalFeatureRangeSession{
				InternalOptionalFeatureTestSession: adengine.InternalClientSession(client).(InternalOptionalFeatureTestSession),
				InternalRangeRead:                  func(context.Context, string, []string) (map[string][][]byte, error) { return attrs, readErr },
			}
			result, err := adservice_directory_settings.New(client).
				OptionalFeatures(context.Background(), admodel.OptionalFeatureQuery{})
			got := result.Features[0]
			if mode == "initial-denied" || mode == "initial-duplicate" {
				if err == nil || result.Complete ||
					got.EnabledScopesState != admodel.AttributePartial {
					t.Fatal(result, err)
				}
				return
			}
			if err != nil || !result.Complete {
				t.Fatal(result, err)
			}
			want := admodel.AttributePresent
			if mode == "absent" {
				want = admodel.AttributeAbsent
			}
			if got.EnabledScopesState != want || len(got.EnabledScopeObjects) != 1 {
				t.Fatal(got)
			}
		})
	}
}

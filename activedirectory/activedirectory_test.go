package activedirectory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/discovery"
)

type compositionSession struct{ closes, reads int }

func (s *compositionSession) InternalStartSearch(
	context.Context,
	model.SearchOptions,
) (model.InternalSearchCursor, error) {
	s.reads++
	return nil, model.ErrInvalidResult
}

func (s *compositionSession) InternalBaseObject(
	context.Context,
	string,
	[]string,
) (map[string][][]byte, error) {
	s.reads++
	return map[string][][]byte{}, nil
}

func (s *compositionSession) InternalRangedBaseObject(
	ctx context.Context,
	dn string,
	properties []string,
) (map[string][][]byte, error) {
	return s.InternalBaseObject(ctx, dn, properties)
}
func (s *compositionSession) InternalClose() error { s.closes++; return nil }

func TestResourceModulesShareSessionLifetime(t *testing.T) {
	session := &compositionSession{}
	raw := engine.InternalNewClient(Config{Timeout: time.Second}, session)
	sdk := compose(raw)
	if _, err := sdk.Directory.RootDSE(context.Background(), RootDSEOptions{}); err != nil {
		t.Fatal(err)
	}
	if session.reads != 1 {
		t.Fatalf("one native read expected, got %d", session.reads)
	}
	if err := sdk.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sdk.Close(); err != nil {
		t.Fatal(err)
	}
	identity, err := IdentityByDN("CN=fixture,DC=example,DC=test")
	if err != nil {
		t.Fatal(err)
	}
	_, userErr := sdk.Users.User(context.Background(), identity, ResolveIdentityOptions{})
	_, groupErr := sdk.Groups.Group(context.Background(), identity, ResolveIdentityOptions{})
	_, discoveryErr := sdk.Discovery.Domain(context.Background(), discovery.DomainOptions{})
	for name, err := range map[string]error{"user": userErr, "group": groupErr, "discovery": discoveryErr} {
		if !errors.Is(err, ErrClosed) {
			t.Errorf("%s after Close: %v", name, err)
		}
	}
	if session.closes != 1 || session.reads != 1 {
		t.Fatalf("shared session: closes=%d reads=%d", session.closes, session.reads)
	}
}

func TestDialRejectsInvalidConfiguration(t *testing.T) {
	client, err := Dial(context.Background(), Config{})
	if client != nil || !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Dial returned %v, %v", client, err)
	}
}

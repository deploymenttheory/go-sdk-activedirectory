package activedirectory

import (
	"errors"
	"strings"
	"testing"
)

const (
	migrationDelegatedDN  = "CN=dmsa,OU=target,DC=example"
	migrationSupersededDN = "CN=legacy,OU=target,DC=example"
)

// migrationSides builds an observed pair in a given state. A nil state leaves
// the attribute absent, which must behave like MigrationNone without being
// recorded as an observed zero.
func migrationSides(delegatedState, supersededState *ServiceAccountMigrationState, linked bool) ServiceAccountMigrationResult {
	var result ServiceAccountMigrationResult
	result.Delegated.State = delegatedState
	result.Superseded.State = supersededState
	if linked {
		d, s := migrationSupersededDN, migrationDelegatedDN
		result.Delegated.ForwardLinkDN = &d
		result.Superseded.ForwardLinkDN = &s
	}
	return result
}

func migrationStatePtr(v ServiceAccountMigrationState) *ServiceAccountMigrationState { return &v }

func planFor(t *testing.T, op migrationOperation, result ServiceAccountMigrationResult) (migrationPlan, error) {
	t.Helper()
	return planServiceAccountMigration(op, result, migrationDelegatedDN, migrationSupersededDN)
}

func changeFor(changes []AttributeChange, attribute string) (AttributeChange, bool) {
	for _, c := range changes {
		if strings.EqualFold(c.Attribute, attribute) {
			return c, true
		}
	}
	return AttributeChange{}, false
}

func TestMigrationStartRequiresACleanPair(t *testing.T) {
	// A clean pair starts: both states none, no links.
	plan, err := planFor(t, migrationStart, migrationSides(nil, nil, false))
	if err != nil {
		t.Fatalf("a clean pair must start: %v", err)
	}
	// Both accounts get state 1 and a forward link to the other.
	if c, ok := changeFor(plan.delegated, dmsaStateAttribute); !ok || string(c.Values[0].Bytes()) != "1" {
		t.Fatalf("delegated state: %+v", c)
	}
	if c, ok := changeFor(plan.delegated, dmsaPrecededByLink); !ok || string(c.Values[0].Bytes()) != migrationSupersededDN {
		t.Fatalf("delegated link: %+v", c)
	}
	if c, ok := changeFor(plan.superseded, supersededState); !ok || string(c.Values[0].Bytes()) != "1" {
		t.Fatalf("superseded state: %+v", c)
	}
	if c, ok := changeFor(plan.superseded, supersededLink); !ok || string(c.Values[0].Bytes()) != migrationDelegatedDN {
		t.Fatalf("superseded link: %+v", c)
	}
	// Starting must never touch the backlinks: the directory maintains them.
	for _, bl := range []string{dmsaPrecededByLinkBL, supersededLinkBL} {
		if _, ok := changeFor(append(plan.delegated, plan.superseded...), bl); ok {
			t.Fatalf("a backlink must never be written: %s", bl)
		}
	}
}

func TestMigrationStartRefusesALiveMigration(t *testing.T) {
	// Re-starting a live migration could repoint a link away from an account
	// mid-transfer, so every non-clean pair is refused.
	for name, result := range map[string]ServiceAccountMigrationResult{
		"already started":   migrationSides(migrationStatePtr(MigrationStarted), migrationStatePtr(MigrationStarted), true),
		"already completed": migrationSides(migrationStatePtr(MigrationCompleted), migrationStatePtr(MigrationCompleted), true),
		"one side started":  migrationSides(migrationStatePtr(MigrationStarted), nil, false),
		"linked but unset":  migrationSides(nil, nil, true),
	} {
		if _, err := planFor(t, migrationStart, result); !errors.Is(err, ErrServiceAccountMigrationState) {
			t.Fatalf("%s: expected ErrServiceAccountMigrationState, got %v", name, err)
		}
	}
}

func TestMigrationCompleteRequiresStartedAndLinked(t *testing.T) {
	started := migrationSides(migrationStatePtr(MigrationStarted), migrationStatePtr(MigrationStarted), true)
	plan, err := planFor(t, migrationComplete, started)
	if err != nil {
		t.Fatalf("a started linked pair must complete: %v", err)
	}
	if c, ok := changeFor(plan.delegated, dmsaStateAttribute); !ok || string(c.Values[0].Bytes()) != "2" {
		t.Fatalf("delegated state: %+v", c)
	}
	if c, ok := changeFor(plan.superseded, supersededState); !ok || string(c.Values[0].Bytes()) != "2" {
		t.Fatalf("superseded state: %+v", c)
	}
	// The observed end state removes the superseded account's SPNs.
	if c, ok := changeFor(plan.superseded, "servicePrincipalName"); !ok || c.Kind != AttributeClear {
		t.Fatalf("superseded SPNs must be cleared: %+v", c)
	}
	// The links are already correct and must not be rewritten.
	if _, ok := changeFor(plan.delegated, dmsaPrecededByLink); ok {
		t.Fatal("completion must not rewrite the forward link")
	}

	// Wrong state is refused.
	if _, err := planFor(t, migrationComplete, migrationSides(nil, nil, false)); !errors.Is(err, ErrServiceAccountMigrationState) {
		t.Fatalf("completing an unstarted pair must be refused, got %v", err)
	}
	// Right state but unpaired is refused separately: completing a one-sided
	// link could join two unrelated migrations.
	unpaired := migrationSides(migrationStatePtr(MigrationStarted), migrationStatePtr(MigrationStarted), false)
	if _, err := planFor(t, migrationComplete, unpaired); !errors.Is(err, ErrServiceAccountMigrationPaired) {
		t.Fatalf("expected ErrServiceAccountMigrationPaired, got %v", err)
	}
}

func TestMigrationUndoStepsBackOneStage(t *testing.T) {
	// Undo of a completed migration returns to started and keeps the links.
	completed := migrationSides(migrationStatePtr(MigrationCompleted), migrationStatePtr(MigrationCompleted), true)
	plan, err := planFor(t, migrationUndo, completed)
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := changeFor(plan.delegated, dmsaStateAttribute); !ok || string(c.Values[0].Bytes()) != "1" {
		t.Fatalf("undo of completed must return to state 1: %+v", c)
	}
	if _, ok := changeFor(plan.delegated, dmsaPrecededByLink); ok {
		t.Fatal("undo of a completed migration must keep the links")
	}
	// It must not re-enable the account or restore SPNs: the contract does not
	// require that, so inventing it would be a fabricated behaviour.
	if _, ok := changeFor(plan.superseded, "userAccountControl"); ok {
		t.Fatal("undo must not change userAccountControl")
	}
	if _, ok := changeFor(plan.superseded, "servicePrincipalName"); ok {
		t.Fatal("undo must not restore service principal names")
	}

	// Undo of a started migration unlinks the pair entirely.
	started := migrationSides(migrationStatePtr(MigrationStarted), migrationStatePtr(MigrationStarted), true)
	plan, err = planFor(t, migrationUndo, started)
	if err != nil {
		t.Fatal(err)
	}
	assertUnlinked(t, plan)

	// A pair with nothing to undo is refused.
	if _, err := planFor(t, migrationUndo, migrationSides(nil, nil, false)); !errors.Is(err, ErrServiceAccountMigrationState) {
		t.Fatalf("undoing a clean pair must be refused, got %v", err)
	}
	// Mismatched states are refused rather than guessed at.
	mixed := migrationSides(migrationStatePtr(MigrationCompleted), migrationStatePtr(MigrationStarted), true)
	if _, err := planFor(t, migrationUndo, mixed); !errors.Is(err, ErrServiceAccountMigrationState) {
		t.Fatalf("mismatched states must be refused, got %v", err)
	}
}

func TestMigrationResetClearsFromEitherState(t *testing.T) {
	for name, result := range map[string]ServiceAccountMigrationResult{
		"started":   migrationSides(migrationStatePtr(MigrationStarted), migrationStatePtr(MigrationStarted), true),
		"completed": migrationSides(migrationStatePtr(MigrationCompleted), migrationStatePtr(MigrationCompleted), true),
		"one sided": migrationSides(migrationStatePtr(MigrationStarted), nil, false),
	} {
		plan, err := planFor(t, migrationReset, result)
		if err != nil {
			t.Fatalf("%s: reset must proceed: %v", name, err)
		}
		assertUnlinked(t, plan)
	}
	// Nothing to clear is reported rather than written as a no-op.
	if _, err := planFor(t, migrationReset, migrationSides(nil, nil, false)); !errors.Is(err, ErrServiceAccountMigrationState) {
		t.Fatalf("resetting a clean pair must be refused, got %v", err)
	}
}

// assertUnlinked checks the contract for undo-started and every reset: all four
// link attributes absent afterwards.
func assertUnlinked(t *testing.T, plan migrationPlan) {
	t.Helper()
	// The dMSA state attribute is mandatory on its class, so it is zeroed
	// rather than removed.
	c, ok := changeFor(plan.delegated, dmsaStateAttribute)
	if !ok || c.Kind != AttributeSet || string(c.Values[0].Bytes()) != "0" {
		t.Fatalf("delegated state must be written as zero, not removed: %+v", c)
	}
	if c, ok := changeFor(plan.delegated, dmsaPrecededByLink); !ok || c.Kind != AttributeClear {
		t.Fatalf("delegated forward link must be cleared: %+v", c)
	}
	// The superseded state is optional and is removed.
	if c, ok := changeFor(plan.superseded, supersededState); !ok || c.Kind != AttributeClear {
		t.Fatalf("superseded state must be cleared: %+v", c)
	}
	if c, ok := changeFor(plan.superseded, supersededLink); !ok || c.Kind != AttributeClear {
		t.Fatalf("superseded forward link must be cleared: %+v", c)
	}
}

func TestMigrationDisableChangePreservesOtherFlags(t *testing.T) {
	// A blind write would discard unrelated flags, so the disable bit is ORed
	// into the observed value.
	object := Object{DistinguishedName: migrationSupersededDN, Attributes: map[string][][]byte{
		"useraccountcontrol": {[]byte("66048")}, // NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD
	}}
	change, err := migrationDisableChange(object)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(change.Values[0].Bytes()); got != "66050" {
		t.Fatalf("expected 66048|2 = 66050, got %s", got)
	}
	// Already disabled stays unchanged rather than toggling.
	object.Attributes["useraccountcontrol"] = [][]byte{[]byte("66050")}
	change, err = migrationDisableChange(object)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(change.Values[0].Bytes()); got != "66050" {
		t.Fatalf("an already disabled account must stay 66050, got %s", got)
	}
	// An absent or unreadable value is an error: disabling from an unknown
	// base would discard flags.
	for name, attrs := range map[string]map[string][][]byte{
		"absent":       {},
		"not a number": {"useraccountcontrol": {[]byte("abc")}},
		"multivalued":  {"useraccountcontrol": {[]byte("1"), []byte("2")}},
	} {
		if _, err := migrationDisableChange(Object{Attributes: attrs}); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}
}

func TestMigrationLinkedRequiresBothDirections(t *testing.T) {
	other := "CN=unrelated,DC=example"
	// A one-sided link is not linked: acting on it could join two unrelated
	// migrations.
	cases := map[string]struct {
		delegated, superseded *string
		want                  bool
	}{
		"both correct":     {&[]string{migrationSupersededDN}[0], &[]string{migrationDelegatedDN}[0], true},
		"delegated only":   {&[]string{migrationSupersededDN}[0], nil, false},
		"superseded only":  {nil, &[]string{migrationDelegatedDN}[0], false},
		"neither":          {nil, nil, false},
		"points elsewhere": {&other, &[]string{migrationDelegatedDN}[0], false},
	}
	for name, c := range cases {
		var result ServiceAccountMigrationResult
		result.Delegated.ForwardLinkDN = c.delegated
		result.Superseded.ForwardLinkDN = c.superseded
		got := dmsaMigrationLinked(result.Delegated, result.Superseded, migrationDelegatedDN, migrationSupersededDN)
		if got != c.want {
			t.Fatalf("%s: linked=%v want %v", name, got, c.want)
		}
	}
}

func TestMigrationStateStringIsExplicitAboutUnknown(t *testing.T) {
	if MigrationNone.String() != "none" || MigrationStarted.String() != "started" || MigrationCompleted.String() != "completed" {
		t.Fatal("known states must have stable names")
	}
	// An unrecognised stored value is reported numerically, never mapped onto
	// a known state.
	if got := ServiceAccountMigrationState(7).String(); got != "unknown(7)" {
		t.Fatalf("unknown state rendered as %q", got)
	}
}

func TestMigrationStateAbsentBehavesAsNoneWithoutClaimingZero(t *testing.T) {
	var side ServiceAccountMigrationSide
	if migrationState(side) != MigrationNone {
		t.Fatal("an absent state must behave as none")
	}
	// The observation itself must stay nil so a caller can tell an absent
	// attribute from a stored zero.
	if side.State != nil {
		t.Fatal("an absent state must not be recorded as an observed zero")
	}
}

func TestMigrationRequiresTwoDistinctIdentities(t *testing.T) {
	client := &Client{}
	// A missing identity is refused before anything is resolved.
	if _, err := client.StartServiceAccountMigration(t.Context(), ServiceAccountMigrationRequest{}); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("expected ErrInvalidIdentity, got %v", err)
	}
	identity, err := IdentityByDN(migrationDelegatedDN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.StartServiceAccountMigration(t.Context(), ServiceAccountMigrationRequest{Identity: identity}); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("a missing superseded account must be refused, got %v", err)
	}
}

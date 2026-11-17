package acceptance

import (
	"errors"
	"strings"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_service_accounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/service_accounts"
)

const (
	InternalMigrationDelegatedDN  = "CN=dmsa,OU=target,DC=example"
	InternalMigrationSupersededDN = "CN=legacy,OU=target,DC=example"
)

// migrationSides builds an observed pair in a given state. A nil state leaves
// the attribute absent, which must behave like MigrationNone without being
// recorded as an observed zero.
func InternalMigrationSides(
	delegatedState, supersededState *admodel.ServiceAccountMigrationState,
	linked bool,
) admodel.ServiceAccountMigrationResult {
	var result admodel.ServiceAccountMigrationResult
	result.Delegated.State = delegatedState
	result.Superseded.State = supersededState
	if linked {
		d, s := InternalMigrationSupersededDN, InternalMigrationDelegatedDN
		result.Delegated.ForwardLinkDN = &d
		result.Superseded.ForwardLinkDN = &s
	}
	return result
}

func InternalMigrationStatePtr(
	v admodel.ServiceAccountMigrationState,
) *admodel.ServiceAccountMigrationState {
	return &v
}

func InternalPlanFor(
	t *testing.T,
	op admodel.InternalMigrationOperation,
	result admodel.ServiceAccountMigrationResult,
) (admodel.InternalMigrationPlan, error) {
	t.Helper()
	return admodel.InternalPlanServiceAccountMigration(
		op,
		result,
		InternalMigrationDelegatedDN,
		InternalMigrationSupersededDN,
	)
}

func InternalChangeFor(
	changes []admodel.AttributeChange,
	attribute string,
) (admodel.AttributeChange, bool) {
	for _, c := range changes {
		if strings.EqualFold(c.Attribute, attribute) {
			return c, true
		}
	}
	return admodel.AttributeChange{}, false
}

func TestMigrationStartRequiresACleanPair(t *testing.T) {
	// A clean pair starts: both states none, no links.
	plan, err := InternalPlanFor(
		t,
		admodel.InternalMigrationStart,
		InternalMigrationSides(nil, nil, false),
	)
	if err != nil {
		t.Fatalf("a clean pair must start: %v", err)
	}
	// Both accounts get state 1 and a forward link to the other.
	if c, ok := InternalChangeFor(
		plan.InternalDelegated,
		admodel.InternalDmsaStateAttribute,
	); !ok ||
		string(c.Values[0].Bytes()) != "1" {
		t.Fatalf("delegated state: %+v", c)
	}
	if c, ok := InternalChangeFor(
		plan.InternalDelegated,
		admodel.InternalDmsaPrecededByLink,
	); !ok ||
		string(c.Values[0].Bytes()) != InternalMigrationSupersededDN {
		t.Fatalf("delegated link: %+v", c)
	}
	if c, ok := InternalChangeFor(
		plan.InternalSuperseded,
		admodel.InternalSupersededState,
	); !ok ||
		string(c.Values[0].Bytes()) != "1" {
		t.Fatalf("superseded state: %+v", c)
	}
	if c, ok := InternalChangeFor(
		plan.InternalSuperseded,
		admodel.InternalSupersededLink,
	); !ok ||
		string(c.Values[0].Bytes()) != InternalMigrationDelegatedDN {
		t.Fatalf("superseded link: %+v", c)
	}
	// Starting must never touch the backlinks: the directory maintains them.
	for _, bl := range []string{admodel.InternalDmsaPrecededByLinkBL, admodel.InternalSupersededLinkBL} {
		if _, ok := InternalChangeFor(
			append(plan.InternalDelegated, plan.InternalSuperseded...),
			bl,
		); ok {
			t.Fatalf("a backlink must never be written: %s", bl)
		}
	}
}

func TestMigrationStartRefusesALiveMigration(t *testing.T) {
	// Re-starting a live migration could repoint a link away from an account
	// mid-transfer, so every non-clean pair is refused.
	for name, result := range map[string]admodel.ServiceAccountMigrationResult{
		"already started":   InternalMigrationSides(InternalMigrationStatePtr(admodel.MigrationStarted), InternalMigrationStatePtr(admodel.MigrationStarted), true),
		"already completed": InternalMigrationSides(InternalMigrationStatePtr(admodel.MigrationCompleted), InternalMigrationStatePtr(admodel.MigrationCompleted), true),
		"one side started":  InternalMigrationSides(InternalMigrationStatePtr(admodel.MigrationStarted), nil, false),
		"linked but unset":  InternalMigrationSides(nil, nil, true),
	} {
		if _, err := InternalPlanFor(
			t,
			admodel.InternalMigrationStart,
			result,
		); !errors.Is(
			err,
			admodel.ErrServiceAccountMigrationState,
		) {
			t.Fatalf("%s: expected ErrServiceAccountMigrationState, got %v", name, err)
		}
	}
}

func TestMigrationCompleteRequiresStartedAndLinked(t *testing.T) {
	started := InternalMigrationSides(
		InternalMigrationStatePtr(admodel.MigrationStarted),
		InternalMigrationStatePtr(admodel.MigrationStarted),
		true,
	)
	plan, err := InternalPlanFor(t, admodel.InternalMigrationComplete, started)
	if err != nil {
		t.Fatalf("a started linked pair must complete: %v", err)
	}
	if c, ok := InternalChangeFor(
		plan.InternalDelegated,
		admodel.InternalDmsaStateAttribute,
	); !ok ||
		string(c.Values[0].Bytes()) != "2" {
		t.Fatalf("delegated state: %+v", c)
	}
	if c, ok := InternalChangeFor(
		plan.InternalSuperseded,
		admodel.InternalSupersededState,
	); !ok ||
		string(c.Values[0].Bytes()) != "2" {
		t.Fatalf("superseded state: %+v", c)
	}
	// The observed end state removes the superseded account's SPNs.
	if c, ok := InternalChangeFor(
		plan.InternalSuperseded,
		"servicePrincipalName",
	); !ok ||
		c.Kind != admodel.AttributeClear {
		t.Fatalf("superseded SPNs must be cleared: %+v", c)
	}
	// The links are already correct and must not be rewritten.
	if _, ok := InternalChangeFor(plan.InternalDelegated, admodel.InternalDmsaPrecededByLink); ok {
		t.Fatal("completion must not rewrite the forward link")
	}

	// Wrong state is refused.
	if _, err := InternalPlanFor(
		t,
		admodel.InternalMigrationComplete,
		InternalMigrationSides(nil, nil, false),
	); !errors.Is(
		err,
		admodel.ErrServiceAccountMigrationState,
	) {
		t.Fatalf("completing an unstarted pair must be refused, got %v", err)
	}
	// Right state but unpaired is refused separately: completing a one-sided
	// link could join two unrelated migrations.
	unpaired := InternalMigrationSides(
		InternalMigrationStatePtr(admodel.MigrationStarted),
		InternalMigrationStatePtr(admodel.MigrationStarted),
		false,
	)
	if _, err := InternalPlanFor(
		t,
		admodel.InternalMigrationComplete,
		unpaired,
	); !errors.Is(
		err,
		admodel.ErrServiceAccountMigrationPaired,
	) {
		t.Fatalf("expected ErrServiceAccountMigrationPaired, got %v", err)
	}
}

func TestMigrationUndoStepsBackOneStage(t *testing.T) {
	// Undo of a completed migration returns to started and keeps the links.
	completed := InternalMigrationSides(
		InternalMigrationStatePtr(admodel.MigrationCompleted),
		InternalMigrationStatePtr(admodel.MigrationCompleted),
		true,
	)
	plan, err := InternalPlanFor(t, admodel.InternalMigrationUndo, completed)
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := InternalChangeFor(
		plan.InternalDelegated,
		admodel.InternalDmsaStateAttribute,
	); !ok ||
		string(c.Values[0].Bytes()) != "1" {
		t.Fatalf("undo of completed must return to state 1: %+v", c)
	}
	if _, ok := InternalChangeFor(plan.InternalDelegated, admodel.InternalDmsaPrecededByLink); ok {
		t.Fatal("undo of a completed migration must keep the links")
	}
	// It must not re-enable the account or restore SPNs: the contract does not
	// require that, so inventing it would be a fabricated behaviour.
	if _, ok := InternalChangeFor(plan.InternalSuperseded, "userAccountControl"); ok {
		t.Fatal("undo must not change userAccountControl")
	}
	if _, ok := InternalChangeFor(plan.InternalSuperseded, "servicePrincipalName"); ok {
		t.Fatal("undo must not restore service principal names")
	}

	// Undo of a started migration unlinks the pair entirely.
	started := InternalMigrationSides(
		InternalMigrationStatePtr(admodel.MigrationStarted),
		InternalMigrationStatePtr(admodel.MigrationStarted),
		true,
	)
	plan, err = InternalPlanFor(t, admodel.InternalMigrationUndo, started)
	if err != nil {
		t.Fatal(err)
	}
	InternalAssertUnlinked(t, plan)

	// A pair with nothing to undo is refused.
	if _, err := InternalPlanFor(
		t,
		admodel.InternalMigrationUndo,
		InternalMigrationSides(nil, nil, false),
	); !errors.Is(
		err,
		admodel.ErrServiceAccountMigrationState,
	) {
		t.Fatalf("undoing a clean pair must be refused, got %v", err)
	}
	// Mismatched states are refused rather than guessed at.
	mixed := InternalMigrationSides(
		InternalMigrationStatePtr(admodel.MigrationCompleted),
		InternalMigrationStatePtr(admodel.MigrationStarted),
		true,
	)
	if _, err := InternalPlanFor(
		t,
		admodel.InternalMigrationUndo,
		mixed,
	); !errors.Is(
		err,
		admodel.ErrServiceAccountMigrationState,
	) {
		t.Fatalf("mismatched states must be refused, got %v", err)
	}
}

func TestMigrationResetClearsFromEitherState(t *testing.T) {
	for name, result := range map[string]admodel.ServiceAccountMigrationResult{
		"started":   InternalMigrationSides(InternalMigrationStatePtr(admodel.MigrationStarted), InternalMigrationStatePtr(admodel.MigrationStarted), true),
		"completed": InternalMigrationSides(InternalMigrationStatePtr(admodel.MigrationCompleted), InternalMigrationStatePtr(admodel.MigrationCompleted), true),
		"one sided": InternalMigrationSides(InternalMigrationStatePtr(admodel.MigrationStarted), nil, false),
	} {
		plan, err := InternalPlanFor(t, admodel.InternalMigrationReset, result)
		if err != nil {
			t.Fatalf("%s: reset must proceed: %v", name, err)
		}
		InternalAssertUnlinked(t, plan)
	}
	// Nothing to clear is reported rather than written as a no-op.
	if _, err := InternalPlanFor(
		t,
		admodel.InternalMigrationReset,
		InternalMigrationSides(nil, nil, false),
	); !errors.Is(
		err,
		admodel.ErrServiceAccountMigrationState,
	) {
		t.Fatalf("resetting a clean pair must be refused, got %v", err)
	}
}

// assertUnlinked checks the contract for undo-started and every reset: all four
// link attributes absent afterwards.
func InternalAssertUnlinked(t *testing.T, plan admodel.InternalMigrationPlan) {
	t.Helper()
	// The dMSA state attribute is mandatory on its class, so it is zeroed
	// rather than removed.
	c, ok := InternalChangeFor(plan.InternalDelegated, admodel.InternalDmsaStateAttribute)
	if !ok || c.Kind != admodel.AttributeSet || string(c.Values[0].Bytes()) != "0" {
		t.Fatalf("delegated state must be written as zero, not removed: %+v", c)
	}
	if c, ok := InternalChangeFor(
		plan.InternalDelegated,
		admodel.InternalDmsaPrecededByLink,
	); !ok ||
		c.Kind != admodel.AttributeClear {
		t.Fatalf("delegated forward link must be cleared: %+v", c)
	}
	// The superseded state is optional and is removed.
	if c, ok := InternalChangeFor(
		plan.InternalSuperseded,
		admodel.InternalSupersededState,
	); !ok ||
		c.Kind != admodel.AttributeClear {
		t.Fatalf("superseded state must be cleared: %+v", c)
	}
	if c, ok := InternalChangeFor(
		plan.InternalSuperseded,
		admodel.InternalSupersededLink,
	); !ok ||
		c.Kind != admodel.AttributeClear {
		t.Fatalf("superseded forward link must be cleared: %+v", c)
	}
}

func TestMigrationDisableChangePreservesOtherFlags(t *testing.T) {
	// A blind write would discard unrelated flags, so the disable bit is ORed
	// into the observed value.
	object := admodel.Object{
		DistinguishedName: InternalMigrationSupersededDN,
		Attributes: map[string][][]byte{
			"useraccountcontrol": {[]byte("66048")}, // NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD
		},
	}
	change, err := admodel.InternalMigrationDisableChange(object)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(change.Values[0].Bytes()); got != "66050" {
		t.Fatalf("expected 66048|2 = 66050, got %s", got)
	}
	// Already disabled stays unchanged rather than toggling.
	object.Attributes["useraccountcontrol"] = [][]byte{[]byte("66050")}
	change, err = admodel.InternalMigrationDisableChange(object)
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
		if _, err := admodel.InternalMigrationDisableChange(
			admodel.Object{Attributes: attrs},
		); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}
}

func TestMigrationLinkedRequiresBothDirections(t *testing.T) {
	other := "CN=unrelated,DC=example"
	// A one-sided link is not linked: acting on it could join two unrelated
	// migrations.
	cases := map[string]struct {
		InternalDelegated, InternalSuperseded *string
		InternalWant                          bool
	}{
		"both correct": {
			&[]string{InternalMigrationSupersededDN}[0],
			&[]string{InternalMigrationDelegatedDN}[0],
			true,
		},
		"delegated only":   {&[]string{InternalMigrationSupersededDN}[0], nil, false},
		"superseded only":  {nil, &[]string{InternalMigrationDelegatedDN}[0], false},
		"neither":          {nil, nil, false},
		"points elsewhere": {&other, &[]string{InternalMigrationDelegatedDN}[0], false},
	}
	for name, c := range cases {
		var result admodel.ServiceAccountMigrationResult
		result.Delegated.ForwardLinkDN = c.InternalDelegated
		result.Superseded.ForwardLinkDN = c.InternalSuperseded
		got := admodel.InternalDmsaMigrationLinked(
			result.Delegated,
			result.Superseded,
			InternalMigrationDelegatedDN,
			InternalMigrationSupersededDN,
		)
		if got != c.InternalWant {
			t.Fatalf("%s: linked=%v want %v", name, got, c.InternalWant)
		}
	}
}

func TestMigrationStateStringIsExplicitAboutUnknown(t *testing.T) {
	if admodel.MigrationNone.String() != "none" || admodel.MigrationStarted.String() != "started" ||
		admodel.MigrationCompleted.String() != "completed" {
		t.Fatal("known states must have stable names")
	}
	// An unrecognised stored value is reported numerically, never mapped onto
	// a known state.
	if got := admodel.ServiceAccountMigrationState(7).String(); got != "unknown(7)" {
		t.Fatalf("unknown state rendered as %q", got)
	}
}

func TestMigrationStateAbsentBehavesAsNoneWithoutClaimingZero(t *testing.T) {
	var side admodel.ServiceAccountMigrationSide
	if admodel.InternalMigrationState(side) != admodel.MigrationNone {
		t.Fatal("an absent state must behave as none")
	}
	// The observation itself must stay nil so a caller can tell an absent
	// attribute from a stored zero.
	if side.State != nil {
		t.Fatal("an absent state must not be recorded as an observed zero")
	}
}

func TestMigrationRequiresTwoDistinctIdentities(t *testing.T) {
	client := &adengine.Client{}
	// A missing identity is refused before anything is resolved.
	if _, err := adservice_service_accounts.New(client).
		StartServiceAccountMigration(t.Context(), admodel.ServiceAccountMigrationRequest{}); !errors.Is(
		err,
		admodel.ErrInvalidIdentity,
	) {
		t.Fatalf("expected ErrInvalidIdentity, got %v", err)
	}
	identity, err := admodel.IdentityByDN(InternalMigrationDelegatedDN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adservice_service_accounts.New(client).
		StartServiceAccountMigration(t.Context(), admodel.ServiceAccountMigrationRequest{Identity: identity}); !errors.Is(
		err,
		admodel.ErrInvalidIdentity,
	) {
		t.Fatalf("a missing superseded account must be refused, got %v", err)
	}
}

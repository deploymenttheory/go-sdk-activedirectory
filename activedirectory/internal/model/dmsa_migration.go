package model

import (
	"errors"
	"strconv"
	"strings"
)

// Delegated managed service account migration links a dMSA to the account it
// supersedes and moves that pair through a small state machine.
//
// The expected end state of each transition is the contract already encoded in
// internal/dmsareference (CheckPhase): started is state 1 on both accounts with
// both forward links set; completed is state 2 on both with the superseded
// account disabled and its SPNs removed; undo of a started migration and every
// reset leave all four link attributes absent.
//
// Two objects are written, and the directory offers no cross-object atomicity
// for them. A migration that writes one and fails the other is reported as
// partial and never compensated automatically.

var (
	ErrServiceAccountMigration = errors.New("invalid delegated managed service account migration")
	// ErrServiceAccountMigrationState means the observed pair is not in the
	// state this transition requires. Nothing is written.
	ErrServiceAccountMigrationState = errors.New(
		"migration is not in the state this operation requires",
	)
	// ErrServiceAccountMigrationPartial means one account was written and the
	// other was not. Reconcile before another attempt; nothing is replayed.
	ErrServiceAccountMigrationPartial = errors.New(
		"migration wrote one account but not the other; reconcile before retrying",
	)
	// ErrServiceAccountMigrationPaired means the two accounts do not reference
	// each other, so operating on them would join unrelated migrations.
	ErrServiceAccountMigrationPaired = errors.New("the two accounts are not linked to each other")
)

const (
	InternalDmsaClass          = "msDS-DelegatedManagedServiceAccount"
	InternalDmsaStateAttribute = "msDS-DelegatedMSAState"
	InternalDmsaPrecededByLink = "msDS-ManagedAccountPrecededByLink"
	InternalSupersededState    = "msDS-SupersededServiceAccountState"
	InternalSupersededLink     = "msDS-SupersededManagedAccountLink"
	// The backlinks are system-maintained. They are read for observation and
	// never written: clearing a forward link clears its backlink.
	InternalDmsaPrecededByLinkBL = "msDS-ManagedAccountPrecededByLinkBL"
	InternalSupersededLinkBL     = "msDS-SupersededManagedAccountLinkBL"
)

// ServiceAccountMigrationState is the stored migration state. Absent and zero
// are both reported as MigrationNone; the state attribute is mandatory on the
// dMSA class, so clearing it means writing zero rather than removing it.
type ServiceAccountMigrationState int64

const (
	MigrationNone      ServiceAccountMigrationState = 0
	MigrationStarted   ServiceAccountMigrationState = 1
	MigrationCompleted ServiceAccountMigrationState = 2
)

func (s ServiceAccountMigrationState) String() string {
	switch s {
	case MigrationNone:
		return "none"
	case MigrationStarted:
		return "started"
	case MigrationCompleted:
		return "completed"
	default:
		return "unknown(" + strconv.FormatInt(int64(s), 10) + ")"
	}
}

// ServiceAccountMigrationRequest names the pair. Identity is the delegated
// account; SupersededAccount is the account it replaces.
type ServiceAccountMigrationRequest struct {
	Identity          Identity
	SupersededAccount Identity
	Partition         string
	Options           ObjectMutationOptions
}

// ServiceAccountMigrationSide is one half of the observed pair.
type ServiceAccountMigrationSide struct {
	Observation IdentityResult
	// State is nil when the attribute was not returned, which is not the same
	// as MigrationNone and is never silently treated as it.
	State *ServiceAccountMigrationState
	// ForwardLinkDN is this account's own link to the other, and BacklinkDN is
	// the system-maintained reverse. Both are reported as read.
	ForwardLinkDN, BacklinkDN *string
	Mutation                  *ObjectMutationResult
}

type ServiceAccountMigrationResult struct {
	Delegated  ServiceAccountMigrationSide
	Superseded ServiceAccountMigrationSide
	// Partial means one account was written and the other was not, so the pair
	// is inconsistent. Nothing is compensated automatically.
	Partial  bool
	Verified bool
	Complete bool
}

func InternalDmsaProperties() []string {
	return []string{
		"objectGUID", "uSNChanged", "objectClass", "name", "sAMAccountName",
		InternalDmsaStateAttribute, InternalDmsaPrecededByLink, InternalDmsaPrecededByLinkBL,
		InternalSupersededState, InternalSupersededLink, InternalSupersededLinkBL,
		"userAccountControl", "servicePrincipalName",
	}
}

// decodeMigrationSide reads the migration fields from either account. The two
// accounts use different attribute names, so the caller states which.
func InternalDecodeMigrationSide(
	object Object,
	stateName, linkName, backlinkName string,
) (side ServiceAccountMigrationSide, err error) {
	d := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	if value := InternalDecodeScalar(&d, stateName, InternalParseInt64); value != nil {
		state := ServiceAccountMigrationState(*value)
		side.State = &state
	}
	side.ForwardLinkDN = d.InternalText(linkName)
	side.BacklinkDN = d.InternalText(backlinkName)
	return side, errors.Join(d.InternalErrors...)
}

func InternalMigrationState(side ServiceAccountMigrationSide) ServiceAccountMigrationState {
	if side.State == nil {
		return MigrationNone
	}
	return *side.State
}

// dmsaMigrationLinked reports whether the pair references each other. A
// one-sided link is not treated as linked: operating on it could join two
// unrelated migrations.
func InternalDmsaMigrationLinked(
	delegated, superseded ServiceAccountMigrationSide,
	delegatedDN, supersededDN string,
) bool {
	forward := delegated.ForwardLinkDN != nil &&
		InternalCentralSameDN(*delegated.ForwardLinkDN, supersededDN)
	reverse := superseded.ForwardLinkDN != nil &&
		InternalCentralSameDN(*superseded.ForwardLinkDN, delegatedDN)
	return forward && reverse
}

type InternalMigrationOperation uint8

const (
	InternalMigrationStart InternalMigrationOperation = iota + 1
	InternalMigrationComplete
	InternalMigrationUndo
	InternalMigrationReset
)

// migrationPlan is the pair of change sets one transition applies.
type InternalMigrationPlan struct {
	InternalDelegated, InternalSuperseded []AttributeChange
}

func InternalMigrationInteger(
	attribute string,
	value ServiceAccountMigrationState,
) AttributeChange {
	return AttributeChange{
		Attribute: attribute,
		Kind:      AttributeSet,
		Values:    []RawValue{NewRawValue([]byte(strconv.FormatInt(int64(value), 10)))},
	}
}

func InternalMigrationLink(attribute, dn string) AttributeChange {
	return AttributeChange{
		Attribute: attribute,
		Kind:      AttributeSet,
		Values:    []RawValue{NewRawValue([]byte(dn))},
	}
}

// planServiceAccountMigration validates the observed pair against the
// transition and renders the changes. It writes nothing.
func InternalPlanServiceAccountMigration(
	operation InternalMigrationOperation,
	result ServiceAccountMigrationResult,
	delegatedDN, supersededDN string,
) (InternalMigrationPlan, error) {
	var plan InternalMigrationPlan
	delegated, superseded := InternalMigrationState(
		result.Delegated,
	), InternalMigrationState(
		result.Superseded,
	)
	linked := InternalDmsaMigrationLinked(
		result.Delegated,
		result.Superseded,
		delegatedDN,
		supersededDN,
	)

	switch operation {
	case InternalMigrationStart:
		// Starting requires a clean pair. Re-starting a live migration could
		// repoint a link away from an account mid-transfer.
		if delegated != MigrationNone || superseded != MigrationNone {
			return plan, ErrServiceAccountMigrationState
		}
		if result.Delegated.ForwardLinkDN != nil || result.Superseded.ForwardLinkDN != nil {
			return plan, ErrServiceAccountMigrationState
		}
		plan.InternalDelegated = []AttributeChange{
			InternalMigrationInteger(InternalDmsaStateAttribute, MigrationStarted),
			InternalMigrationLink(InternalDmsaPrecededByLink, supersededDN),
		}
		plan.InternalSuperseded = []AttributeChange{
			InternalMigrationInteger(InternalSupersededState, MigrationStarted),
			InternalMigrationLink(InternalSupersededLink, delegatedDN),
		}
	case InternalMigrationComplete:
		if delegated != MigrationStarted || superseded != MigrationStarted {
			return plan, ErrServiceAccountMigrationState
		}
		if !linked {
			return plan, ErrServiceAccountMigrationPaired
		}
		plan.InternalDelegated = []AttributeChange{
			InternalMigrationInteger(InternalDmsaStateAttribute, MigrationCompleted),
		}
		plan.InternalSuperseded = []AttributeChange{
			InternalMigrationInteger(InternalSupersededState, MigrationCompleted),
			// Disabling and removing the SPNs are part of the observed end
			// state, not an addition by this SDK.
			{Attribute: "servicePrincipalName", Kind: AttributeClear},
		}
	case InternalMigrationUndo:
		switch {
		case delegated == MigrationCompleted && superseded == MigrationCompleted:
			if !linked {
				return plan, ErrServiceAccountMigrationPaired
			}
			plan.InternalDelegated = []AttributeChange{
				InternalMigrationInteger(InternalDmsaStateAttribute, MigrationStarted),
			}
			plan.InternalSuperseded = []AttributeChange{
				InternalMigrationInteger(InternalSupersededState, MigrationStarted),
			}
		case delegated == MigrationStarted && superseded == MigrationStarted:
			if !linked {
				return plan, ErrServiceAccountMigrationPaired
			}
			plan = InternalMigrationUnlinkPlan()
		default:
			return plan, ErrServiceAccountMigrationState
		}
	case InternalMigrationReset:
		// Reset clears from either live state. A pair with nothing to clear is
		// reported rather than written as a no-op.
		if delegated == MigrationNone && superseded == MigrationNone &&
			result.Delegated.ForwardLinkDN == nil && result.Superseded.ForwardLinkDN == nil {
			return plan, ErrServiceAccountMigrationState
		}
		plan = InternalMigrationUnlinkPlan()
	default:
		return plan, ErrServiceAccountMigration
	}
	return plan, nil
}

// migrationUnlinkPlan clears both forward links and both states. The dMSA
// state attribute is mandatory on its class, so it is written as zero rather
// than removed; the superseded state is optional and is cleared.
func InternalMigrationUnlinkPlan() InternalMigrationPlan {
	return InternalMigrationPlan{
		InternalDelegated: []AttributeChange{
			InternalMigrationInteger(InternalDmsaStateAttribute, MigrationNone),
			{Attribute: InternalDmsaPrecededByLink, Kind: AttributeClear},
		},
		InternalSuperseded: []AttributeChange{
			{Attribute: InternalSupersededState, Kind: AttributeClear},
			{Attribute: InternalSupersededLink, Kind: AttributeClear},
		},
	}
}

// migrationDisablesSuperseded reports whether this transition must also clear
// the superseded account's enabled state, which Complete does.
func InternalMigrationDisablesSuperseded(operation InternalMigrationOperation) bool {
	return operation == InternalMigrationComplete
}

func InternalMigrationOptions(
	request ServiceAccountMigrationRequest,
	properties []string,
) ObjectMutationOptions {
	options := request.Options
	options.Partition = request.Partition
	options.Properties = append(append([]string(nil), options.Properties...), properties...)
	return options
}

// migrationDisableChange clears the enabled state on the superseded account by
// setting the disable bit in its observed userAccountControl. The observed
// value is required: a blind write would discard unrelated flags.
func InternalMigrationDisableChange(object Object) (AttributeChange, error) {
	values := object.Values("userAccountControl")
	value, err := values.Single()
	if err != nil {
		return AttributeChange{}, errors.Join(ErrServiceAccountMigration, err)
	}
	text, err := value.Text()
	if err != nil {
		return AttributeChange{}, err
	}
	current, err := strconv.ParseUint(strings.TrimSpace(text), 10, 32)
	if err != nil {
		return AttributeChange{}, errors.Join(ErrServiceAccountMigration, err)
	}
	const accountDisabled = 0x2
	updated := current | accountDisabled
	return AttributeChange{
		Attribute: "userAccountControl",
		Kind:      AttributeSet,
		Values:    []RawValue{NewRawValue([]byte(strconv.FormatUint(updated, 10)))},
	}, nil
}

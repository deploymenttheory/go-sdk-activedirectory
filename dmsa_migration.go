package activedirectory

import (
	"context"
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
	ErrServiceAccountMigrationState = errors.New("migration is not in the state this operation requires")
	// ErrServiceAccountMigrationPartial means one account was written and the
	// other was not. Reconcile before another attempt; nothing is replayed.
	ErrServiceAccountMigrationPartial = errors.New("migration wrote one account but not the other; reconcile before retrying")
	// ErrServiceAccountMigrationPaired means the two accounts do not reference
	// each other, so operating on them would join unrelated migrations.
	ErrServiceAccountMigrationPaired = errors.New("the two accounts are not linked to each other")
)

const (
	dmsaClass          = "msDS-DelegatedManagedServiceAccount"
	dmsaStateAttribute = "msDS-DelegatedMSAState"
	dmsaPrecededByLink = "msDS-ManagedAccountPrecededByLink"
	supersededState    = "msDS-SupersededServiceAccountState"
	supersededLink     = "msDS-SupersededManagedAccountLink"
	// The backlinks are system-maintained. They are read for observation and
	// never written: clearing a forward link clears its backlink.
	dmsaPrecededByLinkBL = "msDS-ManagedAccountPrecededByLinkBL"
	supersededLinkBL     = "msDS-SupersededManagedAccountLinkBL"
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

func dmsaProperties() []string {
	return []string{
		"objectGUID", "uSNChanged", "objectClass", "name", "sAMAccountName",
		dmsaStateAttribute, dmsaPrecededByLink, dmsaPrecededByLinkBL,
		supersededState, supersededLink, supersededLinkBL,
		"userAccountControl", "servicePrincipalName",
	}
}

// decodeMigrationSide reads the migration fields from either account. The two
// accounts use different attribute names, so the caller states which.
func decodeMigrationSide(object Object, stateName, linkName, backlinkName string) (side ServiceAccountMigrationSide, err error) {
	d := rootDSEDecoder{attributes: object.Attributes}
	if value := decodeScalar(&d, stateName, parseInt64); value != nil {
		state := ServiceAccountMigrationState(*value)
		side.State = &state
	}
	side.ForwardLinkDN = d.text(linkName)
	side.BacklinkDN = d.text(backlinkName)
	return side, errors.Join(d.errors...)
}

func migrationState(side ServiceAccountMigrationSide) ServiceAccountMigrationState {
	if side.State == nil {
		return MigrationNone
	}
	return *side.State
}

// dmsaMigrationLinked reports whether the pair references each other. A
// one-sided link is not treated as linked: operating on it could join two
// unrelated migrations.
func dmsaMigrationLinked(delegated, superseded ServiceAccountMigrationSide, delegatedDN, supersededDN string) bool {
	forward := delegated.ForwardLinkDN != nil && centralSameDN(*delegated.ForwardLinkDN, supersededDN)
	reverse := superseded.ForwardLinkDN != nil && centralSameDN(*superseded.ForwardLinkDN, delegatedDN)
	return forward && reverse
}

// StartServiceAccountMigration links a delegated account to the account it
// supersedes and marks both started.
func (c *Client) StartServiceAccountMigration(ctx context.Context, request ServiceAccountMigrationRequest) (ServiceAccountMigrationResult, error) {
	return c.changeServiceAccountMigration(ctx, request, migrationStart)
}

// CompleteServiceAccountMigration marks a started migration completed. It also
// disables the superseded account and removes its service principal names,
// which is the observed end state of the reference operation.
func (c *Client) CompleteServiceAccountMigration(ctx context.Context, request ServiceAccountMigrationRequest) (ServiceAccountMigrationResult, error) {
	return c.changeServiceAccountMigration(ctx, request, migrationComplete)
}

// UndoServiceAccountMigration steps one stage back: a completed migration
// returns to started, and a started migration is unlinked.
//
// Undoing a completed migration does not re-enable the superseded account or
// restore its service principal names. The reference contract does not require
// it, so this SDK does not invent that restoration.
func (c *Client) UndoServiceAccountMigration(ctx context.Context, request ServiceAccountMigrationRequest) (ServiceAccountMigrationResult, error) {
	return c.changeServiceAccountMigration(ctx, request, migrationUndo)
}

// ResetServiceAccountMigration unlinks the pair from either state, clearing
// both forward links and both states.
func (c *Client) ResetServiceAccountMigration(ctx context.Context, request ServiceAccountMigrationRequest) (ServiceAccountMigrationResult, error) {
	return c.changeServiceAccountMigration(ctx, request, migrationReset)
}

type migrationOperation uint8

const (
	migrationStart migrationOperation = iota + 1
	migrationComplete
	migrationUndo
	migrationReset
)

// migrationPlan is the pair of change sets one transition applies.
type migrationPlan struct {
	delegated, superseded []AttributeChange
}

func migrationInteger(attribute string, value ServiceAccountMigrationState) AttributeChange {
	return AttributeChange{Attribute: attribute, Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(strconv.FormatInt(int64(value), 10)))}}
}

func migrationLink(attribute, dn string) AttributeChange {
	return AttributeChange{Attribute: attribute, Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(dn))}}
}

// planServiceAccountMigration validates the observed pair against the
// transition and renders the changes. It writes nothing.
func planServiceAccountMigration(operation migrationOperation, result ServiceAccountMigrationResult, delegatedDN, supersededDN string) (migrationPlan, error) {
	var plan migrationPlan
	delegated, superseded := migrationState(result.Delegated), migrationState(result.Superseded)
	linked := dmsaMigrationLinked(result.Delegated, result.Superseded, delegatedDN, supersededDN)

	switch operation {
	case migrationStart:
		// Starting requires a clean pair. Re-starting a live migration could
		// repoint a link away from an account mid-transfer.
		if delegated != MigrationNone || superseded != MigrationNone {
			return plan, ErrServiceAccountMigrationState
		}
		if result.Delegated.ForwardLinkDN != nil || result.Superseded.ForwardLinkDN != nil {
			return plan, ErrServiceAccountMigrationState
		}
		plan.delegated = []AttributeChange{
			migrationInteger(dmsaStateAttribute, MigrationStarted),
			migrationLink(dmsaPrecededByLink, supersededDN),
		}
		plan.superseded = []AttributeChange{
			migrationInteger(supersededState, MigrationStarted),
			migrationLink(supersededLink, delegatedDN),
		}
	case migrationComplete:
		if delegated != MigrationStarted || superseded != MigrationStarted {
			return plan, ErrServiceAccountMigrationState
		}
		if !linked {
			return plan, ErrServiceAccountMigrationPaired
		}
		plan.delegated = []AttributeChange{migrationInteger(dmsaStateAttribute, MigrationCompleted)}
		plan.superseded = []AttributeChange{
			migrationInteger(supersededState, MigrationCompleted),
			// Disabling and removing the SPNs are part of the observed end
			// state, not an addition by this SDK.
			{Attribute: "servicePrincipalName", Kind: AttributeClear},
		}
	case migrationUndo:
		switch {
		case delegated == MigrationCompleted && superseded == MigrationCompleted:
			if !linked {
				return plan, ErrServiceAccountMigrationPaired
			}
			plan.delegated = []AttributeChange{migrationInteger(dmsaStateAttribute, MigrationStarted)}
			plan.superseded = []AttributeChange{migrationInteger(supersededState, MigrationStarted)}
		case delegated == MigrationStarted && superseded == MigrationStarted:
			if !linked {
				return plan, ErrServiceAccountMigrationPaired
			}
			plan = migrationUnlinkPlan()
		default:
			return plan, ErrServiceAccountMigrationState
		}
	case migrationReset:
		// Reset clears from either live state. A pair with nothing to clear is
		// reported rather than written as a no-op.
		if delegated == MigrationNone && superseded == MigrationNone &&
			result.Delegated.ForwardLinkDN == nil && result.Superseded.ForwardLinkDN == nil {
			return plan, ErrServiceAccountMigrationState
		}
		plan = migrationUnlinkPlan()
	default:
		return plan, ErrServiceAccountMigration
	}
	return plan, nil
}

// migrationUnlinkPlan clears both forward links and both states. The dMSA
// state attribute is mandatory on its class, so it is written as zero rather
// than removed; the superseded state is optional and is cleared.
func migrationUnlinkPlan() migrationPlan {
	return migrationPlan{
		delegated: []AttributeChange{
			migrationInteger(dmsaStateAttribute, MigrationNone),
			{Attribute: dmsaPrecededByLink, Kind: AttributeClear},
		},
		superseded: []AttributeChange{
			{Attribute: supersededState, Kind: AttributeClear},
			{Attribute: supersededLink, Kind: AttributeClear},
		},
	}
}

// migrationDisablesSuperseded reports whether this transition must also clear
// the superseded account's enabled state, which Complete does.
func migrationDisablesSuperseded(operation migrationOperation) bool {
	return operation == migrationComplete
}

func (c *Client) changeServiceAccountMigration(ctx context.Context, request ServiceAccountMigrationRequest, operation migrationOperation) (ServiceAccountMigrationResult, error) {
	var result ServiceAccountMigrationResult
	if request.Identity.Form() == 0 || request.SupersededAccount.Form() == 0 {
		return result, errors.Join(ErrServiceAccountMigration, ErrInvalidIdentity)
	}
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// Observe both accounts before planning. A transition is decided from what
	// the directory actually holds, never from the caller's assumption.
	var delegatedDN, supersededDN string
	err := c.read(bounded, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		if err := root.Capabilities().RequireADDS("ServiceAccountMigration"); err != nil {
			return err
		}
		options := ResolveIdentityOptions{Partition: request.Partition, Properties: dmsaProperties()}
		result.Delegated.Observation, err = resolveIdentitySession(ctx, c.session, c.config, root, request.Identity, options)
		if err != nil {
			return err
		}
		// The delegated side must really be a dMSA: the superseded side may be
		// a user, computer or managed account, so only this one is class-checked.
		if err := centralAccessClassCheck(*result.Delegated.Observation.Object, dmsaClass); err != nil {
			return errors.Join(ErrServiceAccountMigration, err)
		}
		result.Superseded.Observation, err = resolveIdentitySession(ctx, c.session, c.config, root, request.SupersededAccount, options)
		if err != nil {
			return err
		}
		delegatedDN = result.Delegated.Observation.Object.DistinguishedName
		supersededDN = result.Superseded.Observation.Object.DistinguishedName
		if centralSameDN(delegatedDN, supersededDN) {
			return errors.Join(ErrServiceAccountMigration, ErrInvalidIdentity)
		}
		delegatedSide, delegatedErr := decodeMigrationSide(*result.Delegated.Observation.Object, dmsaStateAttribute, dmsaPrecededByLink, dmsaPrecededByLinkBL)
		supersededSide, supersededErr := decodeMigrationSide(*result.Superseded.Observation.Object, supersededState, supersededLink, supersededLinkBL)
		delegatedSide.Observation = result.Delegated.Observation
		supersededSide.Observation = result.Superseded.Observation
		result.Delegated, result.Superseded = delegatedSide, supersededSide
		return errors.Join(delegatedErr, supersededErr)
	})
	if err != nil {
		return result, err
	}

	plan, err := planServiceAccountMigration(operation, result, delegatedDN, supersededDN)
	if err != nil {
		return result, err
	}
	if migrationDisablesSuperseded(operation) {
		disable, err := migrationDisableChange(*result.Superseded.Observation.Object)
		if err != nil {
			return result, err
		}
		plan.superseded = append(plan.superseded, disable)
	}

	// The two writes are separate modifies with no cross-object atomicity. The
	// delegated account is written first so a failure leaves the superseded
	// account untouched, and the partial state is reported rather than undone.
	// Address both accounts by GUID so a rename between the read and the write
	// cannot redirect either modify.
	delegatedGUID, err := centralAccessGUID(*result.Delegated.Observation.Object)
	if err != nil {
		return result, err
	}
	supersededGUID, err := centralAccessGUID(*result.Superseded.Observation.Object)
	if err != nil {
		return result, err
	}
	delegatedIdentity := objectGUIDIdentity(delegatedGUID)
	supersededIdentity := objectGUIDIdentity(supersededGUID)

	delegatedMutation, err := c.UpdateObject(bounded, UpdateObjectRequest{Identity: delegatedIdentity, Changes: plan.delegated, Options: migrationOptions(request, dmsaProperties())})
	result.Delegated.Mutation = &delegatedMutation
	if err != nil {
		return result, err
	}

	supersededMutation, err := c.UpdateObject(bounded, UpdateObjectRequest{Identity: supersededIdentity, Changes: plan.superseded, Options: migrationOptions(request, dmsaProperties())})
	result.Superseded.Mutation = &supersededMutation
	if err != nil {
		// The first write stands. This is the partial-failure case the pair
		// cannot avoid, and it is surfaced, not compensated.
		result.Partial = true
		return result, errors.Join(ErrServiceAccountMigrationPartial, err)
	}

	result.Verified = delegatedMutation.Verified && supersededMutation.Verified
	result.Complete = result.Verified
	if !result.Verified {
		return result, ErrObjectReadback
	}
	return result, nil
}

func migrationOptions(request ServiceAccountMigrationRequest, properties []string) ObjectMutationOptions {
	options := request.Options
	options.Partition = request.Partition
	options.Properties = append(append([]string(nil), options.Properties...), properties...)
	return options
}

// migrationDisableChange clears the enabled state on the superseded account by
// setting the disable bit in its observed userAccountControl. The observed
// value is required: a blind write would discard unrelated flags.
func migrationDisableChange(object Object) (AttributeChange, error) {
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
	return AttributeChange{Attribute: "userAccountControl", Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(strconv.FormatUint(updated, 10)))}}, nil
}

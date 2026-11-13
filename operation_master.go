package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

var (
	ErrInvalidOperationMasterRequest = errors.New("invalid operation master request")
	ErrOperationMasterCapability     = errors.New("target cannot accept the requested operation master role")
	ErrOperationMasterPermission     = errors.New("operation master access denied")
	ErrOperationMasterUncertain      = errors.New("operation master write outcome is unknown; reconcile before another write")
	ErrOperationMasterReadback       = errors.New("operation master readback did not verify the requested state")
	ErrOperationMasterChanged        = errors.New("operation master state changed before seizure")
	ErrOperationMasterRIDPool        = errors.New("RID pool cannot safely advance by 30000")
)

// OperationMasterRole identifies one of the five FSMO roles.
type OperationMasterRole string

const (
	OperationMasterPDCEmulator          OperationMasterRole = "PDCEmulator"
	OperationMasterRIDMaster            OperationMasterRole = "RIDMaster"
	OperationMasterInfrastructureMaster OperationMasterRole = "InfrastructureMaster"
	OperationMasterSchemaMaster         OperationMasterRole = "SchemaMaster"
	OperationMasterDomainNamingMaster   OperationMasterRole = "DomainNamingMaster"
)

// MoveOperationMasterRolesRequest moves roles to the Client's pinned endpoint.
// Domain roles apply to that server's default domain, independently of
// Config.Partition. Roles are processed in the requested order, stopping on
// the first error. There is no rollback of earlier roles.
type MoveOperationMasterRolesRequest struct {
	Roles []OperationMasterRole
	// Force permits seizure after a definitive transfer failure. Transfer is
	// always attempted first. Permission, capability, and uncertain failures
	// never trigger seizure. RID seizure consumes 30,000 additional RIDs.
	Force bool
}

// Validate checks portable input constraints without contacting a directory.
func (r MoveOperationMasterRolesRequest) Validate() error {
	if len(r.Roles) == 0 || len(r.Roles) > 5 {
		return ErrInvalidOperationMasterRequest
	}
	seen := make(map[OperationMasterRole]bool, len(r.Roles))
	for _, role := range r.Roles {
		if _, ok := operationMasterDefinitions[role]; !ok || seen[role] {
			return ErrInvalidOperationMasterRequest
		}
		seen[role] = true
	}
	return nil
}

// OperationMasterWriteState distinguishes a server acknowledgement from a
// missing response. Rejected means the server returned a failure; it does not
// prove that every server-side step of a transfer had no effect.
type OperationMasterWriteState uint8

const (
	OperationMasterWriteNotAttempted OperationMasterWriteState = iota
	OperationMasterWriteAccepted
	OperationMasterWriteRejected
	OperationMasterWriteUncertain
)

// OperationMasterAttempt preserves the native failure, including LDAP status,
// diagnostic text, and cleanup errors. Diagnostic text may be sensitive.
type OperationMasterAttempt struct {
	State OperationMasterWriteState
	Err   error
}

type OperationMasterStatus string

const (
	OperationMasterNotAttempted OperationMasterStatus = "not-attempted"
	OperationMasterAlreadyOwned OperationMasterStatus = "already-owned"
	OperationMasterTransferred  OperationMasterStatus = "transferred"
	OperationMasterSeized       OperationMasterStatus = "seized"
	OperationMasterFailed       OperationMasterStatus = "failed"
	OperationMasterUncertain    OperationMasterStatus = "uncertain"
)

// OperationMasterOutcome records one requested role. Accepted transfer/seizure
// responses retain their status even if subsequent readback fails; check Err
// and Verified before treating the observation as complete. Readback describes
// this server's local replica, not convergence or effective role activation.
type OperationMasterOutcome struct {
	Role            OperationMasterRole
	Status          OperationMasterStatus
	RoleObjectDN    string
	PreviousOwnerDN string
	ObservedOwnerDN string
	Transfer        OperationMasterAttempt
	Seizure         OperationMasterAttempt
	Verified        bool
	// RID pool values are the complete 64-bit rIDAvailablePool attribute.
	// RequestedRIDPool is populated only when preparing a RID seizure.
	PreviousRIDPool  *uint64
	RequestedRIDPool *uint64
	ObservedRIDPool  *uint64
	Err              error
}

type MoveOperationMasterRolesResult struct {
	TargetDSA string
	Outcomes  []OperationMasterOutcome
}

type operationMasterDefinition struct{ attribute, class string }

var operationMasterDefinitions = map[OperationMasterRole]operationMasterDefinition{
	OperationMasterPDCEmulator:          {"becomePdc", "domainDNS"},
	OperationMasterRIDMaster:            {"becomeRidMaster", "rIDManager"},
	OperationMasterInfrastructureMaster: {"becomeInfrastructureMaster", "infrastructureUpdate"},
	OperationMasterSchemaMaster:         {"becomeSchemaMaster", "dMD"},
	OperationMasterDomainNamingMaster:   {"becomeDomainMaster", "crossRefContainer"},
}

// This optional boundary adds only the feature's native primitive. Existing
// read-only directory sessions need not implement a general mutation API.
type operationMasterSession interface {
	directorySession
	operationMasterModify(context.Context, string, []operationMasterModification) OperationMasterAttempt
}

type operationMasterModification = ldapModification

type operationMasterPlan struct {
	role    OperationMasterRole
	dn      string
	owner   string
	value   []byte
	ridPool *uint64
}

// MoveOperationMasterRoles transfers the selected roles to this connection's
// server using native WinLDAP. It validates the directory, target DSA, and all
// selected role objects before writing. AD LDS accepts schema and naming roles
// only. An RODC, an unsynchronized server, or an unknown directory is rejected.
//
// Force permits an explicit seizure after an acknowledged operationsError,
// unavailable, or unwillingToPerform transfer response and a fresh readback.
// Other failures stop the request. No write is retried, no referral is followed,
// and no reconnect occurs. Loss of a write response retires the connection.
// Cancellation/Close after submission can leave an uncertain write; callers
// must reconcile directory state themselves before making another request.
func (c *Client) MoveOperationMasterRoles(ctx context.Context, request MoveOperationMasterRolesRequest) (MoveOperationMasterRolesResult, error) {
	var result MoveOperationMasterRolesResult
	if err := request.Validate(); err != nil {
		return result, err
	}
	roles := slices.Clone(request.Roles)
	result.Outcomes = make([]OperationMasterOutcome, len(roles))
	for i, role := range roles {
		result.Outcomes[i] = OperationMasterOutcome{Role: role, Status: OperationMasterNotAttempted}
	}
	err := c.read(ctx, func(bounded context.Context) error {
		session, ok := c.session.(operationMasterSession)
		if !ok {
			return ErrUnsupported
		}
		target, plans, err := prepareOperationMasters(bounded, session, roles)
		result.TargetDSA = target
		if err != nil {
			return operationMasterError(err)
		}
		for i, plan := range plans {
			outcome := &result.Outcomes[i]
			outcome.RoleObjectDN, outcome.PreviousOwnerDN = plan.dn, plan.owner
			outcome.PreviousRIDPool = plan.ridPool
		}
		for i, plan := range plans {
			if err := context.Cause(bounded); err != nil {
				return err
			}
			outcome := &result.Outcomes[i]
			moveOperationMaster(bounded, session, target, plan, request.Force, outcome)
			if outcome.Err != nil {
				return fmt.Errorf("%s: %w", plan.role, outcome.Err)
			}
		}
		return nil
	})
	return result, err
}

func prepareOperationMasters(ctx context.Context, session directorySession, roles []OperationMasterRole) (string, []operationMasterPlan, error) {
	attrs, err := session.baseObject(ctx, "", []string{"supportedCapabilities", "dsServiceName", "isSynchronized", "defaultNamingContext", "configurationNamingContext", "schemaNamingContext"})
	if err != nil {
		return "", nil, err
	}
	root, err := decodeRootDSE(attrs, nil)
	if err != nil {
		return "", nil, err
	}
	capabilities := root.Capabilities()
	if capabilities.Type == DirectoryUnknown || capabilities.Has("1.2.840.113556.1.4.1920") || root.IsSynchronized == nil || !*root.IsSynchronized {
		return "", nil, ErrOperationMasterCapability
	}
	for _, role := range roles {
		if capabilities.Type == DirectoryADLDS && role != OperationMasterSchemaMaster && role != OperationMasterDomainNamingMaster {
			return "", nil, &DirectoryCapabilityError{Operation: string(role), Required: DirectoryADDS, Actual: capabilities.Type}
		}
	}
	if root.DSServiceName == nil || *root.DSServiceName == "" {
		return "", nil, fmt.Errorf("%w: missing dsServiceName", ErrInvalidResult)
	}
	dsa, err := session.baseObject(ctx, *root.DSServiceName, []string{"distinguishedName", "objectClass", "msDS-isRODC"})
	if err != nil {
		return "", nil, err
	}
	target, err := operationMasterObject(dsa, "nTDSDSA")
	if err != nil {
		return "", nil, err
	}
	if capabilities.Type == DirectoryADDS {
		d := rootDSEDecoder{attributes: dsa}
		readOnly := decodeScalar(&d, "msDS-isRODC", parseLDAPBool)
		if readOnly == nil || *readOnly || len(d.errors) > 0 {
			return target, nil, errors.Join(ErrOperationMasterCapability, errors.Join(d.errors...))
		}
	}
	plans := make([]operationMasterPlan, 0, len(roles))
	for _, role := range roles {
		plan, err := prepareOperationMaster(ctx, session, root, role)
		if err != nil {
			return target, nil, fmt.Errorf("%s: %w", role, err)
		}
		plans = append(plans, plan)
	}
	return target, plans, nil
}

func prepareOperationMaster(ctx context.Context, session directorySession, root RootDSE, role OperationMasterRole) (operationMasterPlan, error) {
	plan := operationMasterPlan{role: role, value: []byte("1")}
	var base *string
	var prefix string
	switch role {
	case OperationMasterSchemaMaster:
		base = root.SchemaNamingContext
	case OperationMasterDomainNamingMaster:
		base, prefix = root.ConfigurationNamingContext, "CN=Partitions,"
	case OperationMasterInfrastructureMaster:
		base, prefix = root.DefaultNamingContext, "CN=Infrastructure,"
	default:
		base = root.DefaultNamingContext
	}
	if base == nil || *base == "" {
		return plan, fmt.Errorf("%w: missing role naming context", ErrInvalidResult)
	}
	plan.dn = prefix + *base
	if role == OperationMasterRIDMaster {
		domain, err := session.baseObject(ctx, *base, []string{"distinguishedName", "objectClass", "rIDManagerReference"})
		if err != nil {
			return plan, err
		}
		if _, err := operationMasterObject(domain, "domainDNS"); err != nil {
			return plan, err
		}
		plan.dn, err = operationMasterText(domain, "rIDManagerReference")
		if err != nil {
			return plan, err
		}
	}
	attrs, err := session.baseObject(ctx, plan.dn, []string{"distinguishedName", "objectClass", "fSMORoleOwner", "objectSID", "rIDAvailablePool"})
	if err != nil {
		return plan, err
	}
	dn, err := operationMasterObject(attrs, operationMasterDefinitions[role].class)
	if err != nil {
		return plan, err
	}
	if !strings.EqualFold(dn, plan.dn) {
		return plan, fmt.Errorf("%w: role object identity mismatch", ErrInvalidResult)
	}
	plan.dn = dn
	plan.owner, err = operationMasterText(attrs, "fSMORoleOwner")
	if err != nil {
		return plan, err
	}
	if role == OperationMasterPDCEmulator {
		values := attrs["objectsid"]
		if len(values) != 1 || !validDomainSID(values[0]) {
			return plan, fmt.Errorf("%w: missing or invalid binary domain SID", ErrInvalidResult)
		}
		plan.value = slices.Clone(values[0])
	}
	if role == OperationMasterRIDMaster {
		pool, err := operationMasterPool(attrs)
		if err != nil {
			return plan, err
		}
		plan.ridPool = &pool
	}
	return plan, nil
}

func operationMasterObject(attrs map[string][][]byte, class string) (string, error) {
	d := rootDSEDecoder{attributes: attrs}
	classes := d.texts("objectClass")
	if !slices.ContainsFunc(classes, func(value string) bool { return strings.EqualFold(value, class) }) {
		return "", fmt.Errorf("%w: expected %s object", ErrInvalidResult, class)
	}
	if len(d.errors) > 0 {
		return "", errors.Join(d.errors...)
	}
	return operationMasterText(attrs, "distinguishedName")
}

func operationMasterText(attrs map[string][][]byte, name string) (string, error) {
	d := rootDSEDecoder{attributes: attrs}
	value := d.text(name)
	if value == nil || *value == "" || len(d.errors) > 0 {
		return "", fmt.Errorf("%w: missing or malformed %s", ErrInvalidResult, name)
	}
	return *value, nil
}

func operationMasterPool(attrs map[string][][]byte) (uint64, error) {
	value, err := operationMasterText(attrs, "rIDAvailablePool")
	if err != nil {
		return 0, err
	}
	pool, err := strconv.ParseUint(value, 10, 63)
	if err != nil || uint32(pool) > uint32(pool>>32) {
		return 0, ErrOperationMasterRIDPool
	}
	return pool, nil
}

func moveOperationMaster(ctx context.Context, session operationMasterSession, target string, plan operationMasterPlan, force bool, outcome *OperationMasterOutcome) {
	if strings.EqualFold(plan.owner, target) {
		outcome.Status, outcome.ObservedOwnerDN, outcome.Verified = OperationMasterAlreadyOwned, plan.owner, true
		outcome.ObservedRIDPool = plan.ridPool
		return
	}
	outcome.Transfer = session.operationMasterModify(ctx, "", []operationMasterModification{{0, operationMasterDefinitions[plan.role].attribute, plan.value}})
	setOperationMasterAttempt(outcome, outcome.Transfer, OperationMasterTransferred)
	if outcome.Transfer.State == OperationMasterWriteUncertain || outcome.Transfer.State == OperationMasterWriteNotAttempted {
		return
	}
	readbackErr := readOperationMaster(ctx, session, target, plan, outcome)
	if outcome.Transfer.Err == nil {
		outcome.Err = readbackErr
		return
	}
	if outcome.Verified && readbackErr == nil {
		// The role now belongs here, but retain the acknowledged transfer error.
		// A concurrent administrator may have moved it. Never seize it again.
		return
	}
	if !force || !operationMasterMaySeize(outcome.Transfer) || context.Cause(ctx) != nil {
		outcome.Err = errors.Join(outcome.Err, readbackErr)
		return
	}
	// A fresh, well-formed read of the original owner is required. A mismatch
	// or failed readback cannot become permission to overwrite someone else.
	if !errors.Is(readbackErr, ErrOperationMasterReadback) || !strings.EqualFold(outcome.ObservedOwnerDN, plan.owner) {
		outcome.Err = errors.Join(outcome.Err, readbackErr, ErrOperationMasterChanged)
		return
	}
	mods := []operationMasterModification{{1, "fSMORoleOwner", []byte(plan.owner)}, {0, "fSMORoleOwner", []byte(target)}}
	if plan.role == OperationMasterRIDMaster {
		pool := outcome.ObservedRIDPool
		if pool == nil || uint64(uint32(*pool))+30000 > *pool>>32 {
			outcome.Err = errors.Join(outcome.Err, ErrOperationMasterRIDPool)
			return
		}
		next := *pool + 30000
		outcome.RequestedRIDPool = &next
		// All four changes are one LDAP Modify. Deleting the exact observed
		// values guards against lost updates; never use permissive modify.
		mods = append(mods, operationMasterModification{1, "rIDAvailablePool", []byte(strconv.FormatUint(*pool, 10))}, operationMasterModification{0, "rIDAvailablePool", []byte(strconv.FormatUint(next, 10))})
	}
	outcome.Seizure = session.operationMasterModify(ctx, plan.dn, mods)
	setOperationMasterAttempt(outcome, outcome.Seizure, OperationMasterSeized)
	if outcome.Seizure.State == OperationMasterWriteUncertain || outcome.Seizure.State == OperationMasterWriteNotAttempted {
		return
	}
	outcome.Err = errors.Join(outcome.Err, readOperationMaster(ctx, session, target, plan, outcome))
}

func setOperationMasterAttempt(outcome *OperationMasterOutcome, attempt OperationMasterAttempt, success OperationMasterStatus) {
	outcome.Err = operationMasterError(attempt.Err)
	switch attempt.State {
	case OperationMasterWriteAccepted:
		outcome.Status = success
	case OperationMasterWriteUncertain:
		outcome.Status = OperationMasterUncertain
		outcome.Err = errors.Join(ErrOperationMasterUncertain, outcome.Err)
	default:
		outcome.Status = OperationMasterFailed
	}
}

func operationMasterMaySeize(attempt OperationMasterAttempt) bool {
	// Only an unadorned server rejection allows escalation. Cancellation,
	// native cleanup/parser failures, and other joined errors stop here.
	ldapErr, ok := attempt.Err.(*LDAPError)
	return ok && attempt.State == OperationMasterWriteRejected && (ldapErr.Code == 1 || ldapErr.Code == 52 || ldapErr.Code == 53)
}

func operationMasterError(err error) error {
	var ldapErr *LDAPError
	if errors.As(err, &ldapErr) && ldapErr.Code == 50 {
		return errors.Join(ErrOperationMasterPermission, err)
	}
	return err
}

func readOperationMaster(ctx context.Context, session directorySession, target string, plan operationMasterPlan, outcome *OperationMasterOutcome) error {
	outcome.Verified = false
	attrs, err := session.baseObject(ctx, plan.dn, []string{"distinguishedName", "objectClass", "fSMORoleOwner", "rIDAvailablePool"})
	if err != nil {
		return err
	}
	dn, err := operationMasterObject(attrs, operationMasterDefinitions[plan.role].class)
	if err != nil || !strings.EqualFold(dn, plan.dn) {
		return errors.Join(err, ErrInvalidResult)
	}
	owner, err := operationMasterText(attrs, "fSMORoleOwner")
	if err != nil {
		return err
	}
	outcome.ObservedOwnerDN = owner
	if plan.role == OperationMasterRIDMaster {
		pool, err := operationMasterPool(attrs)
		if err != nil {
			return err
		}
		outcome.ObservedRIDPool = &pool
		if requested := outcome.RequestedRIDPool; requested != nil && (pool>>32 != *requested>>32 || uint32(pool) < uint32(*requested)) {
			return ErrOperationMasterReadback
		}
	}
	if !strings.EqualFold(owner, target) {
		return ErrOperationMasterReadback
	}
	outcome.Verified = true
	return nil
}

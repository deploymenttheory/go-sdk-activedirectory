package model

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
	ErrOperationMasterCapability     = errors.New(
		"target cannot accept the requested operation master role",
	)
	ErrOperationMasterPermission = errors.New("operation master access denied")
	ErrOperationMasterUncertain  = errors.New(
		"operation master write outcome is unknown; reconcile before another write",
	)
	ErrOperationMasterReadback = errors.New(
		"operation master readback did not verify the requested state",
	)
	ErrOperationMasterChanged = errors.New("operation master state changed before seizure")
	ErrOperationMasterRIDPool = errors.New("RID pool cannot safely advance by 30000")
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
		if _, ok := InternalOperationMasterDefinitions[role]; !ok || seen[role] {
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

type InternalOperationMasterDefinition struct{ InternalAttribute, InternalClass string }

var InternalOperationMasterDefinitions = map[OperationMasterRole]InternalOperationMasterDefinition{
	OperationMasterPDCEmulator:          {"becomePdc", "domainDNS"},
	OperationMasterRIDMaster:            {"becomeRidMaster", "rIDManager"},
	OperationMasterInfrastructureMaster: {"becomeInfrastructureMaster", "infrastructureUpdate"},
	OperationMasterSchemaMaster:         {"becomeSchemaMaster", "dMD"},
	OperationMasterDomainNamingMaster:   {"becomeDomainMaster", "crossRefContainer"},
}

// This optional boundary adds only the feature's native primitive. Existing
// read-only directory sessions need not implement a general mutation API.
type InternalOperationMasterSession interface {
	InternalDirectorySession
	InternalOperationMasterModify(
		context.Context,
		string,
		[]InternalOperationMasterModification,
	) OperationMasterAttempt
}

type InternalOperationMasterModification = InternalLdapModification

type InternalOperationMasterPlan struct {
	InternalRole    OperationMasterRole
	InternalDn      string
	InternalOwner   string
	InternalValue   []byte
	InternalRidPool *uint64
}

func InternalPrepareOperationMasters(
	ctx context.Context,
	session InternalDirectorySession,
	roles []OperationMasterRole,
) (string, []InternalOperationMasterPlan, error) {
	attrs, err := session.InternalBaseObject(
		ctx,
		"",
		[]string{
			"supportedCapabilities",
			"dsServiceName",
			"isSynchronized",
			"defaultNamingContext",
			"configurationNamingContext",
			"schemaNamingContext",
		},
	)
	if err != nil {
		return "", nil, err
	}
	root, err := InternalDecodeRootDSE(attrs, nil)
	if err != nil {
		return "", nil, err
	}
	capabilities := root.Capabilities()
	if capabilities.Type == DirectoryUnknown || capabilities.Has("1.2.840.113556.1.4.1920") ||
		root.IsSynchronized == nil ||
		!*root.IsSynchronized {
		return "", nil, ErrOperationMasterCapability
	}
	for _, role := range roles {
		if capabilities.Type == DirectoryADLDS && role != OperationMasterSchemaMaster &&
			role != OperationMasterDomainNamingMaster {
			return "", nil, &DirectoryCapabilityError{
				Operation: string(role),
				Required:  DirectoryADDS,
				Actual:    capabilities.Type,
			}
		}
	}
	if root.DSServiceName == nil || *root.DSServiceName == "" {
		return "", nil, fmt.Errorf("%w: missing dsServiceName", ErrInvalidResult)
	}
	dsa, err := session.InternalBaseObject(
		ctx,
		*root.DSServiceName,
		[]string{"distinguishedName", "objectClass", "msDS-isRODC"},
	)
	if err != nil {
		return "", nil, err
	}
	target, err := InternalOperationMasterObject(dsa, "nTDSDSA")
	if err != nil {
		return "", nil, err
	}
	if capabilities.Type == DirectoryADDS {
		d := InternalRootDSEDecoder{InternalAttributes: dsa}
		readOnly := InternalDecodeScalar(&d, "msDS-isRODC", InternalParseLDAPBool)
		if readOnly == nil || *readOnly || len(d.InternalErrors) > 0 {
			return target, nil, errors.Join(
				ErrOperationMasterCapability,
				errors.Join(d.InternalErrors...),
			)
		}
	}
	plans := make([]InternalOperationMasterPlan, 0, len(roles))
	for _, role := range roles {
		plan, err := InternalPrepareOperationMaster(ctx, session, root, role)
		if err != nil {
			return target, nil, fmt.Errorf("%s: %w", role, err)
		}
		plans = append(plans, plan)
	}
	return target, plans, nil
}

func InternalPrepareOperationMaster(
	ctx context.Context,
	session InternalDirectorySession,
	root RootDSE,
	role OperationMasterRole,
) (InternalOperationMasterPlan, error) {
	plan := InternalOperationMasterPlan{InternalRole: role, InternalValue: []byte("1")}
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
	plan.InternalDn = prefix + *base
	if role == OperationMasterRIDMaster {
		domain, err := session.InternalBaseObject(
			ctx,
			*base,
			[]string{"distinguishedName", "objectClass", "rIDManagerReference"},
		)
		if err != nil {
			return plan, err
		}
		if _, err := InternalOperationMasterObject(domain, "domainDNS"); err != nil {
			return plan, err
		}
		plan.InternalDn, err = InternalOperationMasterText(domain, "rIDManagerReference")
		if err != nil {
			return plan, err
		}
	}
	attrs, err := session.InternalBaseObject(
		ctx,
		plan.InternalDn,
		[]string{
			"distinguishedName",
			"objectClass",
			"fSMORoleOwner",
			"objectSID",
			"rIDAvailablePool",
		},
	)
	if err != nil {
		return plan, err
	}
	dn, err := InternalOperationMasterObject(
		attrs,
		InternalOperationMasterDefinitions[role].InternalClass,
	)
	if err != nil {
		return plan, err
	}
	if !strings.EqualFold(dn, plan.InternalDn) {
		return plan, fmt.Errorf("%w: role object identity mismatch", ErrInvalidResult)
	}
	plan.InternalDn = dn
	plan.InternalOwner, err = InternalOperationMasterText(attrs, "fSMORoleOwner")
	if err != nil {
		return plan, err
	}
	if role == OperationMasterPDCEmulator {
		values := attrs["objectsid"]
		if len(values) != 1 || !InternalValidDomainSID(values[0]) {
			return plan, fmt.Errorf("%w: missing or invalid binary domain SID", ErrInvalidResult)
		}
		plan.InternalValue = slices.Clone(values[0])
	}
	if role == OperationMasterRIDMaster {
		pool, err := InternalOperationMasterPool(attrs)
		if err != nil {
			return plan, err
		}
		plan.InternalRidPool = &pool
	}
	return plan, nil
}

func InternalOperationMasterObject(attrs map[string][][]byte, class string) (string, error) {
	d := InternalRootDSEDecoder{InternalAttributes: attrs}
	classes := d.InternalTexts("objectClass")
	if !slices.ContainsFunc(
		classes,
		func(value string) bool { return strings.EqualFold(value, class) },
	) {
		return "", fmt.Errorf("%w: expected %s object", ErrInvalidResult, class)
	}
	if len(d.InternalErrors) > 0 {
		return "", errors.Join(d.InternalErrors...)
	}
	return InternalOperationMasterText(attrs, "distinguishedName")
}

func InternalOperationMasterText(attrs map[string][][]byte, name string) (string, error) {
	d := InternalRootDSEDecoder{InternalAttributes: attrs}
	value := d.InternalText(name)
	if value == nil || *value == "" || len(d.InternalErrors) > 0 {
		return "", fmt.Errorf("%w: missing or malformed %s", ErrInvalidResult, name)
	}
	return *value, nil
}

func InternalOperationMasterPool(attrs map[string][][]byte) (uint64, error) {
	value, err := InternalOperationMasterText(attrs, "rIDAvailablePool")
	if err != nil {
		return 0, err
	}
	pool, err := strconv.ParseUint(value, 10, 63)
	if err != nil || uint32(pool) > uint32(pool>>32) {
		return 0, ErrOperationMasterRIDPool
	}
	return pool, nil
}

func InternalMoveOperationMaster(
	ctx context.Context,
	session InternalOperationMasterSession,
	target string,
	plan InternalOperationMasterPlan,
	force bool,
	outcome *OperationMasterOutcome,
) {
	if strings.EqualFold(plan.InternalOwner, target) {
		outcome.Status, outcome.ObservedOwnerDN, outcome.Verified = OperationMasterAlreadyOwned, plan.InternalOwner, true
		outcome.ObservedRIDPool = plan.InternalRidPool
		return
	}
	outcome.Transfer = session.InternalOperationMasterModify(
		ctx,
		"",
		[]InternalOperationMasterModification{
			{
				0,
				InternalOperationMasterDefinitions[plan.InternalRole].InternalAttribute,
				plan.InternalValue,
			},
		},
	)
	InternalSetOperationMasterAttempt(outcome, outcome.Transfer, OperationMasterTransferred)
	if outcome.Transfer.State == OperationMasterWriteUncertain ||
		outcome.Transfer.State == OperationMasterWriteNotAttempted {
		return
	}
	readbackErr := InternalReadOperationMaster(ctx, session, target, plan, outcome)
	if outcome.Transfer.Err == nil {
		outcome.Err = readbackErr
		return
	}
	if outcome.Verified && readbackErr == nil {
		// The role now belongs here, but retain the acknowledged transfer error.
		// A concurrent administrator may have moved it. Never seize it again.
		return
	}
	if !force || !InternalOperationMasterMaySeize(outcome.Transfer) || context.Cause(ctx) != nil {
		outcome.Err = errors.Join(outcome.Err, readbackErr)
		return
	}
	// A fresh, well-formed read of the original owner is required. A mismatch
	// or failed readback cannot become permission to overwrite someone else.
	if !errors.Is(readbackErr, ErrOperationMasterReadback) ||
		!strings.EqualFold(outcome.ObservedOwnerDN, plan.InternalOwner) {
		outcome.Err = errors.Join(outcome.Err, readbackErr, ErrOperationMasterChanged)
		return
	}
	mods := []InternalOperationMasterModification{
		{1, "fSMORoleOwner", []byte(plan.InternalOwner)},
		{0, "fSMORoleOwner", []byte(target)},
	}
	if plan.InternalRole == OperationMasterRIDMaster {
		pool := outcome.ObservedRIDPool
		if pool == nil || uint64(uint32(*pool))+30000 > *pool>>32 {
			outcome.Err = errors.Join(outcome.Err, ErrOperationMasterRIDPool)
			return
		}
		next := *pool + 30000
		outcome.RequestedRIDPool = &next
		// All four changes are one LDAP Modify. Deleting the exact observed
		// values guards against lost updates; never use permissive modify.
		mods = append(
			mods,
			InternalOperationMasterModification{
				1,
				"rIDAvailablePool",
				[]byte(strconv.FormatUint(*pool, 10)),
			},
			InternalOperationMasterModification{
				0,
				"rIDAvailablePool",
				[]byte(strconv.FormatUint(next, 10)),
			},
		)
	}
	outcome.Seizure = session.InternalOperationMasterModify(ctx, plan.InternalDn, mods)
	InternalSetOperationMasterAttempt(outcome, outcome.Seizure, OperationMasterSeized)
	if outcome.Seizure.State == OperationMasterWriteUncertain ||
		outcome.Seizure.State == OperationMasterWriteNotAttempted {
		return
	}
	outcome.Err = errors.Join(
		outcome.Err,
		InternalReadOperationMaster(ctx, session, target, plan, outcome),
	)
}

func InternalSetOperationMasterAttempt(
	outcome *OperationMasterOutcome,
	attempt OperationMasterAttempt,
	success OperationMasterStatus,
) {
	outcome.Err = InternalOperationMasterError(attempt.Err)
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

func InternalOperationMasterMaySeize(attempt OperationMasterAttempt) bool {
	// Only an unadorned server rejection allows escalation. Cancellation,
	// native cleanup/parser failures, and other joined errors stop here.
	ldapErr, ok := attempt.Err.(*LDAPError)
	return ok && attempt.State == OperationMasterWriteRejected &&
		(ldapErr.Code == 1 || ldapErr.Code == 52 || ldapErr.Code == 53)
}

func InternalOperationMasterError(err error) error {
	var ldapErr *LDAPError
	if errors.As(err, &ldapErr) && ldapErr.Code == 50 {
		return errors.Join(ErrOperationMasterPermission, err)
	}
	return err
}

func InternalReadOperationMaster(
	ctx context.Context,
	session InternalDirectorySession,
	target string,
	plan InternalOperationMasterPlan,
	outcome *OperationMasterOutcome,
) error {
	outcome.Verified = false
	attrs, err := session.InternalBaseObject(
		ctx,
		plan.InternalDn,
		[]string{"distinguishedName", "objectClass", "fSMORoleOwner", "rIDAvailablePool"},
	)
	if err != nil {
		return err
	}
	dn, err := InternalOperationMasterObject(
		attrs,
		InternalOperationMasterDefinitions[plan.InternalRole].InternalClass,
	)
	if err != nil || !strings.EqualFold(dn, plan.InternalDn) {
		return errors.Join(err, ErrInvalidResult)
	}
	owner, err := InternalOperationMasterText(attrs, "fSMORoleOwner")
	if err != nil {
		return err
	}
	outcome.ObservedOwnerDN = owner
	if plan.InternalRole == OperationMasterRIDMaster {
		pool, err := InternalOperationMasterPool(attrs)
		if err != nil {
			return err
		}
		outcome.ObservedRIDPool = &pool
		if requested := outcome.RequestedRIDPool; requested != nil &&
			(pool>>32 != *requested>>32 || uint32(pool) < uint32(*requested)) {
			return ErrOperationMasterReadback
		}
	}
	if !strings.EqualFold(owner, target) {
		return ErrOperationMasterReadback
	}
	outcome.Verified = true
	return nil
}

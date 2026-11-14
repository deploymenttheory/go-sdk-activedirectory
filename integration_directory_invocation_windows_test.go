//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// This harness qualifies the explicit-go-invocation behavioural scenario:
// "Compare the documented Go replacement for preview/confirmation/pass-through
// conventions with the reference operation", expecting that "No implicit
// pipeline or prompt is required; any preview performs no mutation, caller
// intent is explicit, and documented typed return/partial-result behavior
// replaces PassThru."
//
// What this SDK actually offers for the three shell conventions:
//
//   - WhatIf: a `Preview bool` field, which exists on exactly three requests —
//     InstallLocalServiceAccountRequest, UninstallLocalServiceAccountRequest
//     and ResetLocalServiceAccountPasswordRequest. It performs the read-only
//     preparation and the state reading, then returns before the native call.
//     Nothing else in the SDK has a preview flag.
//   - Confirm: there is no prompt and nothing to answer. Intent is a named
//     field on the request — AllowLowering, AcknowledgeIrreversible, Force,
//     Recursive, ForceRemoveLocal — and its absence is a typed refusal rather
//     than a question. The one callback that could prompt,
//     ServiceAccountPasswordPrompt, is supplied by the caller and is never
//     reached by a preview.
//   - PassThru: every operation already returns a typed result carrying the
//     object and the write state — ObjectMutationResult.Before/After/State,
//     LocalServiceAccountResult.Before/After/Attempts,
//     OperationMasterOutcome.ObservedOwnerDN — so there is no switch to set and
//     nothing is withheld by default.
//
// The consequence for coverage is uncomfortable and is recorded rather than
// hidden: 101 operations declare this scenario and every one of them is a
// mutation. Only six can be observed to completion without changing the
// directory, because only those six have a path that reports what would change
// and provably attempts no write:
//
//   - the three local managed service account operations, via Preview;
//   - Set-ADDomainMode and Set-ADForestMode, whose transition to the level the
//     directory already holds returns Unchanged with the object attached and
//     ObjectWriteNotAttempted;
//   - Move-ADDirectoryServerOperationMasterRole, whose already-owned role is
//     reported and verified with no transfer attempted.
//
// Every other operation is enumerated in the artifact with the reason it was
// excluded. For many of them the refusal half alone is observable read-only
// (Remove-* without Recursive, Enable-ADOptionalFeature without
// AcknowledgeIrreversible, Move-ADObject across domains); the scenario needs
// both halves, and their positive half would create, change or delete a real
// object. The absence of an implicit pipeline or provider drive is a property
// of the Go API's shape rather than something a run can observe; the one
// runtime-observable part of it — that a preview never calls the password
// prompt the caller supplied — is recorded per operation.

const invocationScenario = "explicit-go-invocation"

// invocationAbsentAccount is a syntactically valid sAMAccountName, short
// enough to pass the native 15-character name rule, that no lab object holds.
// It makes the refused half a genuine resolution refusal rather than a local
// length rejection.
const invocationAbsentAccount = "adsdk-absent9f$"

// invocationRefusal is one named refusal: a request that must be turned down,
// together with the evidence that turning it down changed nothing. Refusals are
// a slice rather than a flag so a reader sees which request was refused, and so
// an operation cannot qualify on an empty set.
type invocationRefusal struct {
	Name       string `json:"name"`
	Refused    bool   `json:"refused"`
	NoMutation bool   `json:"no_mutation"`
	Detail     string `json:"detail,omitempty"`
}

// invocationObservation is one operation's explicit-go-invocation result. Each
// field is a distinct observation rather than an aggregate, so a reader can see
// which half of the scenario a failure came from, and every observation carries
// the reason it did not hold.
type invocationObservation struct {
	Cmdlet string `json:"cmdlet"`
	// Mechanism names the Go surface that replaces the shell convention, so the
	// artifact says what was actually observed rather than implying a -WhatIf.
	Mechanism string `json:"go_mechanism"`
	// Observable records whether this lab could observe the operation's
	// preview half at all. An operation whose fixture is absent, or whose
	// connection is not the role owner the operation requires, is reported and
	// excluded rather than passed on checks that cannot fail.
	Observable    bool   `json:"observable"`
	NotObservable string `json:"not_observable_reason,omitempty"`
	// PreviewName is the preview-equivalent call this operation offers.
	PreviewName string `json:"preview_name"`
	// PreviewCompleted is the preview reporting its outcome: it ran to
	// completion and said what the state is.
	PreviewCompleted bool `json:"preview_completed"`
	// PreviewNoMutation is the load-bearing half of the contract: the preview
	// submitted nothing and claims no verified effect.
	PreviewNoMutation bool `json:"preview_performed_no_mutation"`
	// PreviewTypedResult is the PassThru replacement: the documented typed
	// result carried the object and its observed state without being asked.
	PreviewTypedResult bool   `json:"preview_returned_typed_state"`
	PreviewDetail      string `json:"preview_detail,omitempty"`
	// PromptInvoked is nil where the operation has no prompt hook to offer. A
	// preview that called one would be an implicit confirmation.
	PromptInvoked *bool               `json:"prompt_invoked"`
	Refusals      []invocationRefusal `json:"refusals"`
	Allocations   int                 `json:"native_allocations_remaining"`
	Passed        bool                `json:"passed"`
}

// qualifies keeps the whole scenario in one testable place. Both halves must
// hold, the preview must have changed nothing, the typed result must have
// carried the state, no prompt may have been reached, and the session must not
// leak. An aggregation that silently became permissive would make every future
// run report success regardless of what the directory did, and the artifact
// would look like evidence.
func (o invocationObservation) qualifies() bool {
	if !o.Observable || len(o.Refusals) == 0 {
		return false
	}
	for _, refusal := range o.Refusals {
		if !refusal.Refused || !refusal.NoMutation {
			return false
		}
	}
	if o.PromptInvoked != nil && *o.PromptInvoked {
		return false
	}
	return o.PreviewCompleted && o.PreviewNoMutation && o.PreviewTypedResult &&
		o.Allocations == 0
}

// invocationExclusion is one operation the harness cannot qualify without
// changing the directory. It is recorded so the artifact cannot be read as
// silence about the other 95 operations in the contract.
type invocationExclusion struct {
	Cmdlet string `json:"cmdlet"`
	Reason string `json:"reason"`
}

// invocationEnvironment is what one read of the lab established about it. It
// holds no credentials and no mutable state.
type invocationEnvironment struct {
	defaultNC   string
	configNC    string
	domainLevel *FunctionalLevel
	forestLevel *FunctionalLevel
	// account is one managed service account visible in this domain, used as
	// the fixture for the three local preview operations. hasAccount is false
	// when none is visible, and accountDetail says why.
	account       Identity
	accountDN     string
	accountKind   ServiceAccountKind
	accountDetail string
	hasAccount    bool
}

type invocationTarget struct {
	cmdlet      string
	mechanism   string
	previewName string
	observe     func(context.Context, *Client, invocationEnvironment, *invocationObservation)
}

// invocationTargets is the set of operations whose preview-equivalent half can
// be observed without changing the directory. Every other operation declaring
// the scenario is classified by invocationExclusionReason.
func invocationTargets() []invocationTarget {
	return []invocationTarget{
		{"Install-ADServiceAccount", "InstallLocalServiceAccountRequest.Preview", "preview-install", observeInstallPreview},
		{"Uninstall-ADServiceAccount", "UninstallLocalServiceAccountRequest.Preview", "preview-uninstall", func(ctx context.Context, c *Client, env invocationEnvironment, o *invocationObservation) {
			observeLocalPreview(ctx, c, env, o, previewUninstall)
		}},
		{"Reset-ADServiceAccountPassword", "ResetLocalServiceAccountPasswordRequest.Preview", "preview-reset", func(ctx context.Context, c *Client, env invocationEnvironment, o *invocationObservation) {
			observeLocalPreview(ctx, c, env, o, previewReset)
		}},
		{"Set-ADDomainMode", "FunctionalLevelTransitionResult.Unchanged with ObjectWriteNotAttempted", "no-op-domain-level", func(ctx context.Context, c *Client, env invocationEnvironment, o *invocationObservation) {
			observeFunctionalLevelNoOp(ctx, c, o, env.defaultNC, env.domainLevel, OperationMasterPDCEmulator, (*Client).SetDomainMode)
		}},
		{"Set-ADForestMode", "FunctionalLevelTransitionResult.Unchanged with ObjectWriteNotAttempted", "no-op-forest-level", func(ctx context.Context, c *Client, env invocationEnvironment, o *invocationObservation) {
			base := ""
			if env.configNC != "" {
				base = "CN=Partitions," + env.configNC
			}
			observeFunctionalLevelNoOp(ctx, c, o, base, env.forestLevel, OperationMasterSchemaMaster, (*Client).SetForestMode)
		}},
		{"Move-ADDirectoryServerOperationMasterRole", "OperationMasterOutcome already-owned with OperationMasterWriteNotAttempted", "no-op-owned-roles", observeOwnedRoleNoOp},
	}
}

// invocationExclusionReason says why an operation declaring this scenario is
// not qualified here, and nothing for one the table observes. It is total: an
// operation the harness does not cover always has a recorded reason.
func invocationExclusionReason(cmdlet string) string {
	for _, target := range invocationTargets() {
		if target.cmdlet == cmdlet {
			return ""
		}
	}
	switch cmdlet {
	case "Enable-ADOptionalFeature", "Disable-ADOptionalFeature":
		return "the explicit AcknowledgeIrreversible intent is refused read-only, but there is no preview and the positive half would change a forest-wide feature that cannot be undone"
	case "Show-ADAuthenticationPolicyExpression":
		return "a headless expression and SDDL API that writes nothing: it has no preview to perform and no withheld object for PassThru to return"
	case "Move-ADDirectoryServer":
		return "no preview exists and the positive half would move a domain controller's server object between sites"
	case "Move-ADObject", "Rename-ADObject", "Restore-ADObject", "Sync-ADObject":
		return "no preview exists; the explicit-intent guards are refused read-only, but the positive half would move, rename, restore or replicate a real object"
	case "Set-ADAccountPassword":
		return "no preview exists; a password request is refused read-only without explicit password bytes, but the positive half would change a credential"
	}
	switch {
	case strings.HasPrefix(cmdlet, "New-"):
		return "creation has no preview: the positive half would create a directory object"
	case strings.HasPrefix(cmdlet, "Remove-"):
		return "deletion has no preview: the explicit Recursive intent is refused read-only, but the positive half would delete a directory object or unlink a real member"
	case strings.HasPrefix(cmdlet, "Set-"), strings.HasPrefix(cmdlet, "Add-"),
		strings.HasPrefix(cmdlet, "Clear-"), strings.HasPrefix(cmdlet, "Enable-"),
		strings.HasPrefix(cmdlet, "Disable-"), strings.HasPrefix(cmdlet, "Grant-"),
		strings.HasPrefix(cmdlet, "Revoke-"), strings.HasPrefix(cmdlet, "Unlock-"):
		return "the request carries explicit intent and returns a typed result, but offers no preview: the positive half would change an existing directory object"
	}
	return "the SDK exposes no preview for this operation, so a complete observation would change the directory"
}

// invocationContractOperations lists every operation whose coverage contract
// declares this scenario, in inventory order.
func invocationContractOperations() ([]string, error) {
	// The lab test binary runs on a guest where this repository is not
	// present, so the harness stages the contract and names it. The
	// repository-relative path remains the fallback, which is what the unit
	// tests on the host use.
	path := os.Getenv("ADSDK_INVOCATION_CONTRACT")
	if path == "" {
		path = "coverage/inventory.json"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Windows PowerShell UTF8 output may include the BOM.
	if len(data) >= 3 && string(data[:3]) == "\xef\xbb\xbf" {
		data = data[3:]
	}
	var inventory struct {
		Operations []struct {
			Cmdlet    string `json:"cmdlet"`
			Scenarios []struct {
				Name string `json:"name"`
			} `json:"scenarios"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(data, &inventory); err != nil {
		return nil, err
	}
	cmdlets := make([]string, 0, 128)
	for _, operation := range inventory.Operations {
		for _, scenario := range operation.Scenarios {
			if scenario.Name == invocationScenario {
				cmdlets = append(cmdlets, operation.Cmdlet)
				break
			}
		}
	}
	if len(cmdlets) == 0 {
		return nil, errors.New("no operation in the contract declares " + invocationScenario)
	}
	return cmdlets, nil
}

// invocationDetail reports why an observation did not hold. It records only the
// error's own text, which the SDK already redacts.
func invocationDetail(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// previewCall runs one local service account operation's preview. Each has its
// own request type, so the table binds one call per operation.
type previewCall func(context.Context, *Client, Identity) (LocalServiceAccountResult, error)

func previewInstall(ctx context.Context, c *Client, identity Identity) (LocalServiceAccountResult, error) {
	return c.InstallLocalServiceAccount(ctx, InstallLocalServiceAccountRequest{Identity: identity, Preview: true})
}

func previewUninstall(ctx context.Context, c *Client, identity Identity) (LocalServiceAccountResult, error) {
	return c.UninstallLocalServiceAccount(ctx, UninstallLocalServiceAccountRequest{Identity: identity, Preview: true})
}

func previewReset(ctx context.Context, c *Client, identity Identity) (LocalServiceAccountResult, error) {
	return c.ResetLocalServiceAccountPassword(ctx, ResetLocalServiceAccountPasswordRequest{Identity: identity, Preview: true})
}

// localServiceAccountRefusal is a refused preview: the request failed, nothing
// was reported complete or verified, and no native call was attempted.
func localServiceAccountRefusal(name string, result LocalServiceAccountResult, err error) invocationRefusal {
	return invocationRefusal{
		Name:       name,
		Refused:    err != nil && !result.Complete && !result.Verified,
		NoMutation: len(result.Attempts) == 0 && !result.PartialEffectsPossible,
		Detail:     invocationDetail(err),
	}
}

// functionalLevelRefusal is a refused transition. The named sentinel is
// required: a transition refused for some other reason is not evidence that
// this one's intent guard holds.
func functionalLevelRefusal(name string, want error, result FunctionalLevelTransitionResult, err error) invocationRefusal {
	return invocationRefusal{
		Name:       name,
		Refused:    err != nil && errors.Is(err, want) && !result.Unchanged && !result.PreflightComplete,
		NoMutation: result.Mutation.State == ObjectWriteNotAttempted && !result.Mutation.PartialEffectsPossible,
		Detail:     invocationDetail(err),
	}
}

// operationMasterUntouched reports that no role write was attempted, for either
// phase of every requested role.
func operationMasterUntouched(result MoveOperationMasterRolesResult) bool {
	for _, outcome := range result.Outcomes {
		if outcome.Transfer.State != OperationMasterWriteNotAttempted ||
			outcome.Seizure.State != OperationMasterWriteNotAttempted {
			return false
		}
	}
	return true
}

// invocationLowerLevel is the highest documented functional level below the
// current one. It is the level used to observe that lowering is refused without
// explicit intent; nothing is below Windows 2000.
func invocationLowerLevel(level FunctionalLevel) (FunctionalLevel, bool) {
	for candidate := int(level) - 1; candidate >= 0; candidate-- {
		if knownFunctionalLevel(FunctionalLevel(candidate)) {
			return FunctionalLevel(candidate), true
		}
	}
	return 0, false
}

// localServiceAccountPreviewRefusals is the refused half for one local preview
// operation: a request with no identity at all, refused before the host or the
// directory is read, and a preview of an account the directory does not hold.
func localServiceAccountPreviewRefusals(ctx context.Context, c *Client, call previewCall) []invocationRefusal {
	refusals := make([]invocationRefusal, 0, 2)
	result, err := call(ctx, c, Identity{})
	refusals = append(refusals, localServiceAccountRefusal("preview-without-an-identity", result, err))
	absent, absentErr := IdentityByAccountName(invocationAbsentAccount)
	if absentErr != nil {
		return refusals
	}
	result, err = call(ctx, c, absent)
	return append(refusals, localServiceAccountRefusal("preview-of-an-absent-account", result, err))
}

// observeLocalPreview observes one local managed service account preview. The
// preview is the SDK's documented WhatIf replacement: it performs the
// read-only preparation and the installed-state reading, then returns before
// the native call, which is why no Attempt may be recorded.
func observeLocalPreview(ctx context.Context, c *Client, env invocationEnvironment, o *invocationObservation, call previewCall) {
	if !env.hasAccount {
		o.NotObservable = env.accountDetail
		o.Refusals = localServiceAccountPreviewRefusals(ctx, c, call)
		return
	}
	result, err := call(ctx, c, env.account)
	o.PreviewDetail = invocationDetail(err)
	switch {
	case errors.Is(err, ErrServiceAccountHost):
		// A local operation on a host that cannot hold this account is a lab
		// condition, not a contract breach.
		o.NotObservable = "this host cannot hold the visible managed service account: " + invocationDetail(err)
	case errors.Is(err, ErrServiceAccountNotInstalled):
		// The reset preview reads the installed state and refuses before it can
		// report anything, so its preview half is simply not available here.
		o.NotObservable = "the visible managed service account is not installed on this host, so this preview is refused before it reports: " + invocationDetail(err)
	default:
		o.Observable = true
		o.PreviewCompleted = err == nil && result.Preview && result.Complete
		o.PreviewNoMutation = len(result.Attempts) == 0 && !result.PartialEffectsPossible &&
			!result.Verified && result.After == nil
		o.PreviewTypedResult = result.Account != nil && result.Before != nil &&
			result.NativeAccountName != "" && result.Host.ComputerName != ""
	}
	o.Refusals = localServiceAccountPreviewRefusals(ctx, c, call)
}

// observeInstallPreview adds the one runtime-observable part of the "no prompt"
// half to the install preview: the caller's own password prompt is supplied and
// must not be reached, because a preview that asked for a password would be an
// implicit confirmation.
func observeInstallPreview(ctx context.Context, c *Client, env invocationEnvironment, o *invocationObservation) {
	observeLocalPreview(ctx, c, env, o, previewInstall)
	if !env.hasAccount {
		return
	}
	prompted := false
	_, err := c.InstallLocalServiceAccount(ctx, InstallLocalServiceAccountRequest{
		Identity: env.account,
		Preview:  true,
		PasswordPrompt: func(context.Context, ServiceAccount) ([]byte, error) {
			prompted = true
			return nil, errors.New("a preview must not ask for a password")
		},
	})
	o.PromptInvoked = &prompted
	if err != nil && o.PreviewDetail == "" {
		o.PreviewDetail = "prompt probe: " + invocationDetail(err)
	}
}

// observeFunctionalLevelNoOp observes a transition to the level the directory
// already holds. That path reports the current level with the object attached
// and returns without submitting anything, which is this operation's preview
// equivalent, and its refused half is a lowering that was never asked for.
//
// Only the role owner is ever asked: the operation reads the role owner before
// anything else and refuses otherwise, so a connection that is not the owner
// cannot observe either half.
func observeFunctionalLevelNoOp(ctx context.Context, c *Client, o *invocationObservation, dn string, level *FunctionalLevel, role OperationMasterRole, set func(*Client, context.Context, FunctionalLevelTransitionRequest) (FunctionalLevelTransitionResult, error)) {
	if dn == "" {
		o.NotObservable = "the connection did not report the naming context this operation targets"
		return
	}
	if level == nil {
		o.NotObservable = "the connection does not advertise the functional level this operation sets"
		return
	}
	owned, detail := invocationOwnedRoles(ctx, c)
	if !slices.Contains(owned, role) {
		o.NotObservable = "the connected server does not own the " + string(role) +
			" role, which this operation requires before it reads anything: " + detail
		return
	}
	identity, err := IdentityByDN(dn)
	if err != nil {
		o.NotObservable = "unusable target name: " + invocationDetail(err)
		return
	}

	// The requested level is the level the directory already reports, so the
	// documented no-op path is the one taken. The SDK compares the advertised
	// level with the authoritative attribute before anything else, so a lab
	// where the two disagree refuses every transition and observes neither half.
	result, err := set(c, ctx, FunctionalLevelTransitionRequest{Identity: identity, Level: *level})
	o.PreviewDetail = invocationDetail(err)
	if errors.Is(err, ErrFunctionalLevelPrerequisite) || errors.Is(err, ErrFunctionalLevelRoleOwner) {
		o.NotObservable = "this directory refuses every transition before reporting its level: " + invocationDetail(err)
	} else {
		o.Observable = true
		o.PreviewCompleted = err == nil && result.Unchanged
		o.PreviewNoMutation = result.Mutation.State == ObjectWriteNotAttempted &&
			!result.Mutation.PartialEffectsPossible && !result.PreflightComplete
		o.PreviewTypedResult = result.Current != nil && *result.Current == *level &&
			result.Mutation.Before != nil && result.Mutation.After != nil &&
			result.Mutation.TargetDN != "" && result.Mutation.Verified
	}

	// An unrecognised level is refused without contacting anything.
	const unknownLevel = FunctionalLevel(99)
	unknown, unknownErr := set(c, ctx, FunctionalLevelTransitionRequest{Identity: identity, Level: unknownLevel})
	o.Refusals = append(o.Refusals, functionalLevelRefusal(
		"unknown-level-refused-without-contact", ErrInvalidFunctionalLevel, unknown, unknownErr))

	// The intent half: lowering is refused unless the caller said so, and the
	// refusal happens before the transition's own prerequisites are read.
	lower, ok := invocationLowerLevel(*level)
	if !ok {
		o.PreviewDetail += " lowering refusal not observable: no documented level below the current one"
		return
	}
	lowered, loweredErr := set(c, ctx, FunctionalLevelTransitionRequest{Identity: identity, Level: lower})
	o.Refusals = append(o.Refusals, functionalLevelRefusal(
		"lowering-without-explicit-intent", ErrFunctionalLevelLowering, lowered, loweredErr))
}

// invocationOwnedRoles reads which operation master roles this connection's own
// server already holds, through the same preparation the move itself performs.
// Only those roles are ever requested: an already-owned role is reported and
// verified with no write attempted, while asking for a role another server
// holds would transfer it.
func invocationOwnedRoles(ctx context.Context, c *Client) ([]OperationMasterRole, string) {
	all := []OperationMasterRole{
		OperationMasterPDCEmulator, OperationMasterRIDMaster, OperationMasterInfrastructureMaster,
		OperationMasterSchemaMaster, OperationMasterDomainNamingMaster,
	}
	owned := make([]OperationMasterRole, 0, len(all))
	detail := make([]string, 0, len(all))
	for _, role := range all {
		// One role per read: a role object this directory does not serve must
		// not hide the ownership of the others.
		err := c.read(ctx, func(bounded context.Context) error {
			target, plans, err := prepareOperationMasters(bounded, c.session, []OperationMasterRole{role})
			if err != nil {
				return err
			}
			if len(plans) == 1 && target != "" && strings.EqualFold(plans[0].owner, target) {
				owned = append(owned, role)
			}
			return nil
		})
		if err != nil {
			detail = append(detail, string(role)+"="+err.Error())
		}
	}
	return owned, strings.Join(detail, "; ")
}

// observeOwnedRoleNoOp observes the role move's documented no-op: a role this
// connection already owns is reported, verified and left alone. Ownership is
// re-read here, on this session, immediately before the request, so the request
// can only ever name roles this server already holds.
func observeOwnedRoleNoOp(ctx context.Context, c *Client, env invocationEnvironment, o *invocationObservation) {
	owned, detail := invocationOwnedRoles(ctx, c)
	if len(owned) == 0 {
		o.NotObservable = "this connection owns no operation master role, so every request would move one: " + detail
		return
	}
	roles := slices.Clone(owned)
	request := MoveOperationMasterRolesRequest{Roles: roles}
	if err := request.Validate(); err != nil {
		o.NotObservable = "the owned roles do not form a valid request: " + invocationDetail(err)
		return
	}
	result, err := c.MoveOperationMasterRoles(ctx, request)
	o.Observable = true
	o.PreviewDetail = invocationDetail(err)
	o.PreviewNoMutation = operationMasterUntouched(result) && len(result.Outcomes) == len(roles)
	completed := err == nil && len(result.Outcomes) == len(roles)
	typed := result.TargetDSA != "" && len(result.Outcomes) == len(roles)
	for _, outcome := range result.Outcomes {
		completed = completed && outcome.Status == OperationMasterAlreadyOwned && outcome.Err == nil
		typed = typed && outcome.Verified && outcome.RoleObjectDN != "" &&
			outcome.ObservedOwnerDN != "" && strings.EqualFold(outcome.ObservedOwnerDN, result.TargetDSA)
	}
	o.PreviewCompleted = completed
	o.PreviewTypedResult = typed

	// Both refusals are decided by the request itself, before the directory is
	// contacted: no role selected, and the same role named twice.
	empty, emptyErr := c.MoveOperationMasterRoles(ctx, MoveOperationMasterRolesRequest{})
	o.Refusals = append(o.Refusals, invocationRefusal{
		Name:       "no-role-selected-refused-without-contact",
		Refused:    errors.Is(emptyErr, ErrInvalidOperationMasterRequest) && len(empty.Outcomes) == 0,
		NoMutation: operationMasterUntouched(empty) && empty.TargetDSA == "",
		Detail:     invocationDetail(emptyErr),
	})
	repeated, repeatedErr := c.MoveOperationMasterRoles(ctx, MoveOperationMasterRolesRequest{
		Roles: []OperationMasterRole{roles[0], roles[0]},
	})
	o.Refusals = append(o.Refusals, invocationRefusal{
		Name:       "repeated-role-refused-without-contact",
		Refused:    errors.Is(repeatedErr, ErrInvalidOperationMasterRequest) && len(repeated.Outcomes) == 0,
		NoMutation: operationMasterUntouched(repeated) && repeated.TargetDSA == "",
		Detail:     invocationDetail(repeatedErr),
	})
}

// The outer harness supplies the endpoint only inside an owned run. This test
// never starts PowerShell, operates a VM, or changes the directory: every call
// is a read, a preview, a documented no-op, or a refused request. Ordinary go
// test invocations skip it.
func TestDirectoryInvocationSweepLab(t *testing.T) {
	endpoint := os.Getenv("ADSDK_INVOCATION_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires the opt-in isolated directory invocation harness")
	}
	resultPath := os.Getenv("ADSDK_INVOCATION_RESULT")
	runID := os.Getenv("ADSDK_INVOCATION_RUN_ID")
	if resultPath == "" || runID == "" {
		t.Fatal("an endpoint, a run identity and a fresh result path are required")
	}
	artifact := struct {
		SchemaVersion       int                     `json:"schema_version"`
		Scope               string                  `json:"scope"`
		Scenario            string                  `json:"scenario"`
		RunID               string                  `json:"run_id"`
		Endpoint            string                  `json:"endpoint"`
		RuntimeOS           string                  `json:"runtime_os"`
		RuntimeArchitecture string                  `json:"runtime_architecture"`
		Started             time.Time               `json:"started"`
		Finished            time.Time               `json:"finished"`
		Passed              bool                    `json:"passed"`
		FullTicketComplete  bool                    `json:"full_ticket_complete"`
		FailureStage        string                  `json:"failure_stage,omitempty"`
		ContractOperations  int                     `json:"contract_operations"`
		QualifiedOperations int                     `json:"qualified_operations"`
		ServiceAccount      string                  `json:"service_account_fixture,omitempty"`
		ServiceAccountNote  string                  `json:"service_account_detail,omitempty"`
		Operations          []invocationObservation `json:"operations"`
		Excluded            []invocationExclusion   `json:"excluded_operations"`
	}{
		SchemaVersion: 1, Scope: "directory-explicit-go-invocation", Scenario: invocationScenario,
		RunID: runID, Endpoint: endpoint, RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH,
		Started: time.Now().UTC(), Operations: []invocationObservation{},
		Excluded: []invocationExclusion{},
	}
	stage := "start"
	// FailureStage records where the run first went wrong. Reading the
	// then-current stage at defer time names the last stage reached instead,
	// which points a reader at the wrong place.
	failedAt := ""
	fail := func(format string, args ...any) {
		if failedAt == "" {
			failedAt = stage
		}
		t.Errorf(format, args...)
	}
	defer func() {
		artifact.Finished = time.Now().UTC()
		artifact.Passed = !t.Failed()
		if t.Failed() {
			artifact.FailureStage = failedAt
		}
		data, err := json.MarshalIndent(artifact, "", "  ")
		if err != nil {
			t.Error("cannot encode invocation artifact")
			return
		}
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Error("cannot create fresh invocation artifact")
			return
		}
		_, writeErr := file.Write(append(data, '\n'))
		if closeErr := file.Close(); writeErr != nil || closeErr != nil {
			t.Error("cannot finish invocation artifact")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// withSession dials the endpoint, runs the observations against it, and
	// closes it. The allocation total is returned so a leak is attributed to
	// the session that caused it.
	withSession := func(fn func(*Client)) (int, error) {
		client, err := Dial(ctx, Config{Endpoint: Endpoint{Host: endpoint, Port: 389}, Timeout: 60 * time.Second})
		if err != nil {
			return 0, err
		}
		var counts searchNativeCounts
		client.session.(*ldapSession).api = countedSearchAPI(&counts)
		if fn != nil {
			fn(client)
		}
		closeErr := client.Close()
		return sweepAllocations(counts), closeErr
	}

	// The contract is enumerated first: an operation this harness cannot
	// observe is recorded with its reason, so the artifact covers the whole
	// scenario rather than only the observable part of it.
	stage = "coverage-contract"
	contract, err := invocationContractOperations()
	if err != nil {
		// The artifact claims to account for every operation declaring this
		// scenario. Without the contract it cannot, so the run stops here and
		// records where it stopped.
		fail("cannot read the coverage contract this artifact would cite: %v", err)
		return
	}
	artifact.ContractOperations = len(contract)
	covered := map[string]bool{}
	for _, target := range invocationTargets() {
		covered[target.cmdlet] = true
	}
	for _, cmdlet := range contract {
		if covered[cmdlet] {
			continue
		}
		reason := invocationExclusionReason(cmdlet)
		if reason == "" {
			fail("%s is neither observed nor given a reason for exclusion", cmdlet)
			continue
		}
		artifact.Excluded = append(artifact.Excluded, invocationExclusion{Cmdlet: cmdlet, Reason: reason})
	}

	stage = "lab-environment"
	env := invocationEnvironment{}
	if _, err := withSession(func(c *Client) {
		root, readErr := c.RootDSE(ctx, RootDSEOptions{})
		if readErr != nil {
			fail("cannot read the connection's own naming contexts and levels: %v", readErr)
			return
		}
		if root.DefaultNamingContext != nil {
			env.defaultNC = *root.DefaultNamingContext
		}
		if root.ConfigurationNamingContext != nil {
			env.configNC = *root.ConfigurationNamingContext
		}
		if root.DomainFunctionality != nil {
			level := FunctionalLevel(*root.DomainFunctionality)
			env.domainLevel = &level
		}
		if root.ForestFunctionality != nil {
			level := FunctionalLevel(*root.ForestFunctionality)
			env.forestLevel = &level
		}
		if env.defaultNC == "" {
			fail("the connection did not report a default naming context")
			return
		}
		// One managed service account is the fixture for the three local
		// previews. The well-known container is read explicitly: a subtree read
		// of the domain root reports references to its subordinate naming
		// contexts rather than chasing them, which would be an incomplete read.
		base := "CN=Managed Service Accounts," + env.defaultNC
		accounts, readErr := c.ServiceAccounts(ctx, SearchOptions{Base: base, Scope: ScopeSubtree, PageSize: 64})
		switch {
		case readErr != nil:
			env.accountDetail = "no managed service account fixture: " + readErr.Error()
			return
		case !accounts.Observation.Complete:
			env.accountDetail = "no managed service account fixture: " + base + " was not read to completion"
			return
		}
		chosen := -1
		for i, account := range accounts.Accounts {
			if account.DistinguishedName == "" {
				continue
			}
			// A group managed account is preferred: a standalone one with a
			// visible association to another computer is refused by the install
			// preparation itself, which is a different scenario.
			if chosen < 0 || (account.Kind == ServiceAccountGroupManaged &&
				accounts.Accounts[chosen].Kind != ServiceAccountGroupManaged) {
				chosen = i
			}
		}
		if chosen < 0 {
			env.accountDetail = "no managed service account fixture: " + base + " holds none"
			return
		}
		identity, identityErr := IdentityByDN(accounts.Accounts[chosen].DistinguishedName)
		if identityErr != nil {
			env.accountDetail = "unusable managed service account fixture: " + identityErr.Error()
			return
		}
		env.account, env.accountDN = identity, accounts.Accounts[chosen].DistinguishedName
		env.accountKind, env.hasAccount = accounts.Accounts[chosen].Kind, true
	}); err != nil {
		fail("native dial failed: %v", err)
		return
	}
	artifact.ServiceAccount, artifact.ServiceAccountNote = env.accountDN, env.accountDetail

	stage = "operation-sweep"
	for _, target := range invocationTargets() {
		o := invocationObservation{
			Cmdlet: target.cmdlet, Mechanism: target.mechanism, PreviewName: target.previewName,
			Refusals: []invocationRefusal{},
		}
		// Each operation is observed on its own freshly dialled session, which
		// is how a caller scopes a client and how the endpoint sweep qualified.
		leaked, err := withSession(func(c *Client) { target.observe(ctx, c, env, &o) })
		if err != nil {
			o.PreviewDetail += " session: " + err.Error()
		}
		o.Allocations = leaked
		o.Passed = o.qualifies()
		switch {
		case !o.Observable:
			// Not a failure of the SDK: this lab cannot offer the operation's
			// preview half. Recorded so the artifact cannot be read as evidence
			// for it.
			t.Logf("%s: preview half not observable: %s", target.cmdlet, o.NotObservable)
		case !o.Passed:
			fail("%s: invocation observation incomplete: %+v", target.cmdlet, o)
		default:
			artifact.QualifiedOperations++
		}
		artifact.Operations = append(artifact.Operations, o)
	}

	// A run in which nothing was observable is not evidence of anything, and
	// must not be recorded as a pass.
	stage = "qualification"
	if artifact.QualifiedOperations == 0 {
		fail("no operation in the invocation table was observable; this run qualifies nothing")
	}

	if !t.Failed() {
		stage = "complete"
	}
	t.Logf("explicit Go invocation observed for %d of %d operations on %s; %d excluded as unobservable without a mutation; full ticket qualification remains incomplete",
		artifact.QualifiedOperations, artifact.ContractOperations, endpoint, len(artifact.Excluded))
}

// The decision logic above runs only inside an opt-in lab harness, so without
// these tests nothing exercises it. An aggregation that silently became
// permissive would make every future run report success regardless of what the
// directory did, and the lab artifact would look like evidence.

func passingInvocationObservation() invocationObservation {
	prompted := false
	return invocationObservation{
		Cmdlet:             "Install-ADServiceAccount",
		Mechanism:          "InstallLocalServiceAccountRequest.Preview",
		Observable:         true,
		PreviewName:        "preview-install",
		PreviewCompleted:   true,
		PreviewNoMutation:  true,
		PreviewTypedResult: true,
		PromptInvoked:      &prompted,
		Refusals: []invocationRefusal{
			{Name: "preview-without-an-identity", Refused: true, NoMutation: true},
			{Name: "preview-of-an-absent-account", Refused: true, NoMutation: true},
		},
		Allocations: 0,
	}
}

// Every input must be load-bearing. Withholding any single one must withhold
// the qualification, including the native allocation balance.
func TestInvocationObservationRequiresEveryHalf(t *testing.T) {
	if !passingInvocationObservation().qualifies() {
		t.Fatal("the fully satisfied observation does not qualify")
	}
	prompted := true
	for _, mutation := range []struct {
		name  string
		apply func(*invocationObservation)
	}{
		{"observable", func(o *invocationObservation) { o.Observable = false }},
		{"preview completed", func(o *invocationObservation) { o.PreviewCompleted = false }},
		{"preview performed no mutation", func(o *invocationObservation) { o.PreviewNoMutation = false }},
		{"preview returned typed state", func(o *invocationObservation) { o.PreviewTypedResult = false }},
		{"prompt not invoked", func(o *invocationObservation) { o.PromptInvoked = &prompted }},
		{"any refusal at all", func(o *invocationObservation) { o.Refusals = nil }},
		{"first refusal refused", func(o *invocationObservation) { o.Refusals[0].Refused = false }},
		{"last refusal refused", func(o *invocationObservation) { o.Refusals[1].Refused = false }},
		{"first refusal changed nothing", func(o *invocationObservation) { o.Refusals[0].NoMutation = false }},
		{"last refusal changed nothing", func(o *invocationObservation) { o.Refusals[1].NoMutation = false }},
		{"native allocations balanced", func(o *invocationObservation) { o.Allocations = 1 }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			o := passingInvocationObservation()
			o.Refusals = slices.Clone(o.Refusals)
			mutation.apply(&o)
			if o.qualifies() {
				t.Fatalf("the observation still qualified without %q", mutation.name)
			}
		})
	}
}

// An operation with no prompt hook is not asked about one, so a nil
// PromptInvoked must neither qualify it by default nor disqualify it.
func TestInvocationObservationTreatsAbsentPromptAsNeutral(t *testing.T) {
	o := passingInvocationObservation()
	o.PromptInvoked = nil
	if !o.qualifies() {
		t.Fatal("an operation with no prompt hook was disqualified for having no prompt observation")
	}
	o.PreviewNoMutation = false
	if o.qualifies() {
		t.Fatal("an absent prompt observation excused a preview that mutated")
	}
}

// A refused preview is only evidence if the request actually failed and left
// no native attempt behind.
func TestLocalServiceAccountRefusalRequiresFailureAndCleanState(t *testing.T) {
	refused := localServiceAccountRefusal("named", LocalServiceAccountResult{}, errors.New("boom"))
	if !refused.Refused || !refused.NoMutation || refused.Detail != "boom" {
		t.Fatalf("a bare refusal was not recorded as one: %+v", refused)
	}
	if refused.Name != "named" {
		t.Fatal("the refusal lost its name")
	}
	for _, test := range []struct {
		name   string
		result LocalServiceAccountResult
		err    error
		kept   bool
		clean  bool
	}{
		{"no error at all", LocalServiceAccountResult{}, nil, false, true},
		{"reported complete", LocalServiceAccountResult{Complete: true}, errors.New("boom"), false, true},
		{"reported verified", LocalServiceAccountResult{Verified: true}, errors.New("boom"), false, true},
		{"native attempt recorded", LocalServiceAccountResult{
			Attempts: []LocalServiceAccountAttempt{{Operation: "install"}},
		}, errors.New("boom"), true, false},
		{"partial effects possible", LocalServiceAccountResult{PartialEffectsPossible: true}, errors.New("boom"), true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := localServiceAccountRefusal("named", test.result, test.err)
			if got.Refused != test.kept || got.NoMutation != test.clean {
				t.Fatalf("refused=%t no-mutation=%t, want %t and %t", got.Refused, got.NoMutation, test.kept, test.clean)
			}
		})
	}
}

// A transition refused for some other reason is not evidence that this
// operation's own intent guard holds.
func TestFunctionalLevelRefusalRequiresTheNamedError(t *testing.T) {
	want := ErrFunctionalLevelLowering
	if got := functionalLevelRefusal("named", want, FunctionalLevelTransitionResult{}, want); !got.Refused || !got.NoMutation {
		t.Fatalf("the named refusal was not recorded: %+v", got)
	}
	for _, test := range []struct {
		name   string
		result FunctionalLevelTransitionResult
		err    error
		kept   bool
		clean  bool
	}{
		{"no error at all", FunctionalLevelTransitionResult{}, nil, false, true},
		{"a different refusal", FunctionalLevelTransitionResult{}, ErrInvalidFunctionalLevel, false, true},
		{"reported unchanged", FunctionalLevelTransitionResult{Unchanged: true}, want, false, true},
		{"preflight ran", FunctionalLevelTransitionResult{PreflightComplete: true}, want, false, true},
		{"write accepted", FunctionalLevelTransitionResult{
			Mutation: ObjectMutationResult{State: ObjectWriteAccepted},
		}, want, true, false},
		{"write rejected after submission", FunctionalLevelTransitionResult{
			Mutation: ObjectMutationResult{State: ObjectWriteRejected},
		}, want, true, false},
		{"partial effects possible", FunctionalLevelTransitionResult{
			Mutation: ObjectMutationResult{PartialEffectsPossible: true},
		}, want, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := functionalLevelRefusal("named", want, test.result, test.err)
			if got.Refused != test.kept || got.NoMutation != test.clean {
				t.Fatalf("refused=%t no-mutation=%t, want %t and %t", got.Refused, got.NoMutation, test.kept, test.clean)
			}
		})
	}
}

// Either phase of any requested role having been submitted means the no-op was
// not one.
func TestOperationMasterUntouchedDetectsEveryAttempt(t *testing.T) {
	owned := MoveOperationMasterRolesResult{Outcomes: []OperationMasterOutcome{
		{Role: OperationMasterPDCEmulator, Status: OperationMasterAlreadyOwned},
		{Role: OperationMasterRIDMaster, Status: OperationMasterAlreadyOwned},
	}}
	if !operationMasterUntouched(owned) {
		t.Fatal("two already-owned roles were reported as written")
	}
	for _, test := range []struct {
		name  string
		apply func(*OperationMasterOutcome)
	}{
		{"transfer accepted", func(o *OperationMasterOutcome) { o.Transfer.State = OperationMasterWriteAccepted }},
		{"transfer rejected", func(o *OperationMasterOutcome) { o.Transfer.State = OperationMasterWriteRejected }},
		{"transfer uncertain", func(o *OperationMasterOutcome) { o.Transfer.State = OperationMasterWriteUncertain }},
		{"seizure accepted", func(o *OperationMasterOutcome) { o.Seizure.State = OperationMasterWriteAccepted }},
		{"seizure uncertain", func(o *OperationMasterOutcome) { o.Seizure.State = OperationMasterWriteUncertain }},
	} {
		t.Run(test.name, func(t *testing.T) {
			for i := range owned.Outcomes {
				result := MoveOperationMasterRolesResult{Outcomes: slices.Clone(owned.Outcomes)}
				test.apply(&result.Outcomes[i])
				if operationMasterUntouched(result) {
					t.Fatalf("outcome %d hid a %s", i, test.name)
				}
			}
		})
	}
}

// The lowering refusal needs a level the reference documents below the current
// one. Choosing an undocumented level would be refused as unknown instead, and
// would not observe the intent guard at all.
func TestInvocationLowerLevelSelectsADocumentedLevel(t *testing.T) {
	for _, test := range []struct {
		current FunctionalLevel
		want    FunctionalLevel
		ok      bool
	}{
		{FunctionalLevelWindows2025, FunctionalLevelWindows2016, true},
		{FunctionalLevelWindows2016, FunctionalLevelWindows2012R2, true},
		{FunctionalLevelWindows2008, FunctionalLevelWindows2003, true},
		{FunctionalLevelWindows2003Interim, FunctionalLevelWindows2000, true},
		{FunctionalLevelWindows2000, 0, false},
	} {
		got, ok := invocationLowerLevel(test.current)
		if ok != test.ok || (ok && got != test.want) {
			t.Fatalf("below %d: got %d/%t, want %d/%t", test.current, got, ok, test.want, test.ok)
		}
		if ok && !knownFunctionalLevel(got) {
			t.Fatalf("below %d: %d is not a documented level", test.current, got)
		}
	}
}

// The table is a claim about the coverage contract: each row says it observes
// one operation's explicit-go-invocation scenario. A row naming an operation
// that has no such scenario, or a duplicate row, would make the artifact cite
// evidence for something the contract does not ask for. Every operation the
// table does not cover must carry a recorded reason, so the artifact accounts
// for the whole scenario rather than only its observable part.
func TestInvocationTableMatchesCoverageContract(t *testing.T) {
	contract, err := invocationContractOperations()
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, cmdlet := range contract {
		declared[cmdlet] = true
	}
	seen := map[string]bool{}
	for _, target := range invocationTargets() {
		if seen[target.cmdlet] {
			t.Errorf("%s appears twice in the invocation table", target.cmdlet)
		}
		seen[target.cmdlet] = true
		if !declared[target.cmdlet] {
			t.Errorf("%s has no %s scenario in the coverage contract", target.cmdlet, invocationScenario)
		}
		if target.mechanism == "" || target.previewName == "" || target.observe == nil {
			t.Errorf("%s does not name the Go mechanism it observes", target.cmdlet)
		}
	}
	if len(seen) == 0 {
		t.Fatal("the invocation table is empty")
	}
	for _, cmdlet := range contract {
		if seen[cmdlet] {
			if invocationExclusionReason(cmdlet) != "" {
				t.Errorf("%s is both observed and excluded", cmdlet)
			}
			continue
		}
		if invocationExclusionReason(cmdlet) == "" {
			t.Errorf("%s is neither observed nor given a reason for exclusion", cmdlet)
		}
	}
}

//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_computers "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/computers"
	adservice_groups "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/groups"
	adservice_organizational_units "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/organizational_units"
	adservice_users "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/users"
)

// This harness is the mutating counterpart to the read-side sweeps. It takes
// each object class a caller would model as a resource through a full
// create/update/delete cycle against a real directory, and records both halves
// of every lifecycle scenario the coverage contract asks for.
//
// It writes. Every fixture it creates lives under one organizational unit it
// also creates, and the run is not recorded as passing unless that unit and
// everything beneath it is gone at the end — absence proved by a read, not
// assumed from a delete returning no error.

// lifecycleAttribute names the attributes the update scenarios use. They are
// chosen for properties that hold on every class under test rather than for
// convenience, so one table drives all five kinds:
//
//   - extensionName is multi-valued, carries Unicode string syntax, is
//     available on every class under test, and belongs to no typed projection,
//     so add/remove/replace/clear are all observable on it. It is the "raw
//     extension attribute" the scenario asks for.
//
//     description was the obvious first choice and is wrong. Its schema says
//     isSingleValued=False, but AD DS enforces a single value on user, group
//     and computer regardless — the reference module reports "Multiple values
//     were specified for an attribute that can have only one value", and the
//     server returns LDAP 20. It is also a typed property on four of the five
//     classes, so a two-value write additionally breaks the typed readback
//     ("attribute description has invalid syntax or cardinality"). Measured on
//     the lab across all five classes before switching.
//
//   - displayName is single-valued and also on top, so a typed property update
//     has somewhere to land that the raw changes are not touching.
//
//   - undefined is syntactically valid and not in the schema, so the server
//     refuses it for a schema reason on every class. A per-class attribute
//     would make the failure half mean something different for each kind.
const (
	InternalLifecycleMultiValued = "extensionName"
	InternalLifecycleSingle      = "displayName"
	InternalLifecycleUndefined   = "sdkNoSuchAttributeForQualification"
)

// lifecycleTarget is one object class and the typed entry points that create,
// change and remove it. The closures exist because every class has its own
// request type; the scenarios they evidence are identical, which is the whole
// reason to drive them from one table.
type InternalLifecycleTarget struct {
	InternalKind string
	// The coverage operations whose scenarios these observations evidence.
	InternalCreateCmdlet, InternalUpdateCmdlet, InternalRemoveCmdlet string
	// class is the schema class the create must actually produce. A create that
	// succeeds but produces another class is a failure, not a pass.
	InternalClass string
	// container is true for classes that may hold children, which is what makes
	// the non-leaf and recursive delete boundaries observable at all.
	InternalContainer bool
	// protectedByDefault records classes this SDK protects on creation without
	// being asked. Their first delete attempt must be refused, and that refusal
	// is the deletion scenario's failure half rather than an obstacle.
	InternalProtectedByDefault bool

	InternalCreate func(context.Context, *adengine.Client, admodel.Identity, string, admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error)
	// createWith exercise the create-time halves of the update scenarios: a
	// caller setting attributes and typed properties as it creates a resource,
	// which is the most-used path of all and the one the lifecycle sweep does
	// not reach, because that one creates with naming inputs alone.
	//
	// createWithProperties is nil for the generic object path, which has no
	// typed property layer: there the explicit attribute map is the typed
	// instance, and the harness records that rather than inventing one.
	InternalCreateWithAttributes func(context.Context, *adengine.Client, admodel.Identity, string, map[string][]admodel.RawValue, admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error)
	InternalCreateWithProperties func(context.Context, *adengine.Client, admodel.Identity, string, string, admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error)
	InternalUpdateRaw            func(context.Context, *adengine.Client, admodel.Identity, []admodel.AttributeChange, admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error)
	InternalUpdateTyped          func(context.Context, *adengine.Client, admodel.Identity, string, admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error)
	InternalUnprotect            func(context.Context, *adengine.Client, admodel.Identity, admodel.ObjectMutationOptions) error
	InternalRemove               func(context.Context, *adengine.Client, admodel.Identity, bool, admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error)
}

func InternalLifecycleTargets() []InternalLifecycleTarget {
	text := func(value string) *string { return &value }
	return []InternalLifecycleTarget{
		{
			InternalKind:         "user",
			InternalClass:        "user",
			InternalCreateCmdlet: "New-ADUser",
			InternalUpdateCmdlet: "Set-ADUser",
			InternalRemoveCmdlet: "Remove-ADUser",
			InternalCreateWithAttributes: func(ctx context.Context, c *adengine.Client, parent admodel.Identity, name string, attrs map[string][]admodel.RawValue, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_users.New(c).
					CreateUser(ctx, admodel.CreateUserRequest{Parent: parent, Name: name, Attributes: attrs, Options: o})
				return result.Creation, err
			},
			InternalCreateWithProperties: func(ctx context.Context, c *adengine.Client, parent admodel.Identity, name, value string, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_users.New(c).CreateUser(ctx, admodel.CreateUserRequest{
					Parent: parent, Name: name,
					Properties: admodel.UserProperties{Description: &value}, Options: o,
				})
				return result.Creation, err
			},
			InternalCreate: func(ctx context.Context, c *adengine.Client, parent admodel.Identity, name string, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_users.New(c).
					CreateUser(ctx, admodel.CreateUserRequest{Parent: parent, Name: name, Options: o})
				return result.Creation, err
			},
			InternalUpdateRaw: func(ctx context.Context, c *adengine.Client, id admodel.Identity, changes []admodel.AttributeChange, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_users.New(c).
					UpdateUser(ctx, admodel.UpdateUserRequest{Identity: id, Changes: changes, Options: o})
				return result.Mutation, err
			},
			InternalUpdateTyped: func(ctx context.Context, c *adengine.Client, id admodel.Identity, value string, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_users.New(c).UpdateUser(ctx, admodel.UpdateUserRequest{
					Identity:   id,
					Properties: admodel.UserProperties{DisplayName: text(value)},
					Options:    o,
				})
				return result.Mutation, err
			},
			InternalRemove: func(ctx context.Context, c *adengine.Client, id admodel.Identity, _ bool, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_users.New(c).
					DeleteUser(ctx, admodel.DeleteUserRequest{Identity: id, Options: o})
				return result.Mutation, err
			},
		},
		{
			InternalKind:         "group",
			InternalClass:        "group",
			InternalCreateCmdlet: "New-ADGroup",
			InternalUpdateCmdlet: "Set-ADGroup",
			InternalRemoveCmdlet: "Remove-ADGroup",
			InternalCreateWithAttributes: func(ctx context.Context, c *adengine.Client, parent admodel.Identity, name string, attrs map[string][]admodel.RawValue, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_groups.New(c).CreateGroup(ctx, admodel.CreateGroupRequest{
					Parent:     parent,
					Name:       name,
					Category:   admodel.GroupSecurity,
					Scope:      admodel.GroupGlobal,
					Attributes: attrs,
					Options:    o,
				})
				return result.Mutation, err
			},
			InternalCreateWithProperties: func(ctx context.Context, c *adengine.Client, parent admodel.Identity, name, value string, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_groups.New(c).CreateGroup(ctx, admodel.CreateGroupRequest{
					Parent:      parent,
					Name:        name,
					Category:    admodel.GroupSecurity,
					Scope:       admodel.GroupGlobal,
					Description: &value,
					Options:     o,
				})
				return result.Mutation, err
			},
			InternalCreate: func(ctx context.Context, c *adengine.Client, parent admodel.Identity, name string, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_groups.New(c).CreateGroup(ctx, admodel.CreateGroupRequest{
					Parent:   parent,
					Name:     name,
					Category: admodel.GroupSecurity,
					Scope:    admodel.GroupGlobal,
					Options:  o,
				})
				return result.Mutation, err
			},
			InternalUpdateRaw: func(ctx context.Context, c *adengine.Client, id admodel.Identity, changes []admodel.AttributeChange, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_groups.New(c).
					UpdateGroup(ctx, admodel.UpdateGroupRequest{Identity: id, Changes: changes, Options: o})
				return result.Mutation, err
			},
			InternalUpdateTyped: func(ctx context.Context, c *adengine.Client, id admodel.Identity, value string, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_groups.New(c).
					UpdateGroup(ctx, admodel.UpdateGroupRequest{Identity: id, DisplayName: text(value), Options: o})
				return result.Mutation, err
			},
			InternalRemove: func(ctx context.Context, c *adengine.Client, id admodel.Identity, _ bool, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_groups.New(c).
					DeleteGroup(ctx, admodel.DeleteGroupRequest{Identity: id, Options: o})
				return result.Mutation, err
			},
		},
		{
			InternalKind:         "computer",
			InternalClass:        "computer",
			InternalCreateCmdlet: "New-ADComputer",
			InternalUpdateCmdlet: "Set-ADComputer",
			InternalRemoveCmdlet: "Remove-ADComputer",
			InternalCreateWithAttributes: func(ctx context.Context, c *adengine.Client, parent admodel.Identity, name string, attrs map[string][]admodel.RawValue, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_computers.New(c).
					CreateComputer(ctx, admodel.CreateComputerRequest{Parent: parent, Name: name, Attributes: attrs, Options: o})
				return result.Creation, err
			},
			InternalCreateWithProperties: func(ctx context.Context, c *adengine.Client, parent admodel.Identity, name, value string, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_computers.New(c).
					CreateComputer(ctx, admodel.CreateComputerRequest{
						Parent: parent, Name: name,
						Properties: admodel.ComputerProperties{Description: &value}, Options: o,
					})
				return result.Creation, err
			},
			InternalCreate: func(ctx context.Context, c *adengine.Client, parent admodel.Identity, name string, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_computers.New(c).
					CreateComputer(ctx, admodel.CreateComputerRequest{Parent: parent, Name: name, Options: o})
				return result.Creation, err
			},
			InternalUpdateRaw: func(ctx context.Context, c *adengine.Client, id admodel.Identity, changes []admodel.AttributeChange, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_computers.New(c).
					UpdateComputer(ctx, admodel.UpdateComputerRequest{Identity: id, Changes: changes, Options: o})
				return result.Mutation, err
			},
			InternalUpdateTyped: func(ctx context.Context, c *adengine.Client, id admodel.Identity, value string, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_computers.New(c).
					UpdateComputer(ctx, admodel.UpdateComputerRequest{
						Identity:   id,
						Properties: admodel.ComputerProperties{DisplayName: text(value)},
						Options:    o,
					})
				return result.Mutation, err
			},
			InternalRemove: func(ctx context.Context, c *adengine.Client, id admodel.Identity, recursive bool, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_computers.New(c).
					DeleteComputer(ctx, admodel.DeleteComputerRequest{Identity: id, Recursive: recursive, Options: o})
				return result.Mutation, err
			},
		},
		{
			InternalKind:         "organizational unit",
			InternalClass:        "organizationalUnit",
			InternalCreateCmdlet: "New-ADOrganizationalUnit",
			InternalUpdateCmdlet: "Set-ADOrganizationalUnit",
			InternalRemoveCmdlet: "Remove-ADOrganizationalUnit",
			InternalCreateWithAttributes: func(ctx context.Context, c *adengine.Client, parent admodel.Identity, name string, attrs map[string][]admodel.RawValue, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_organizational_units.New(c).
					CreateOrganizationalUnit(ctx, admodel.CreateOrganizationalUnitRequest{
						Parent: parent, Name: name, Attributes: attrs,
						ProtectedFromAccidentalDeletion: new(bool), Options: o,
					})
				return result.Object, err
			},
			InternalCreateWithProperties: func(ctx context.Context, c *adengine.Client, parent admodel.Identity, name, value string, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_organizational_units.New(c).
					CreateOrganizationalUnit(ctx, admodel.CreateOrganizationalUnitRequest{
						Parent:                          parent,
						Name:                            name,
						Properties:                      admodel.OUProperties{Description: &value},
						ProtectedFromAccidentalDeletion: new(bool),
						Options:                         o,
					})
				return result.Object, err
			},
			InternalContainer:          true,
			InternalProtectedByDefault: true,
			InternalCreate: func(ctx context.Context, c *adengine.Client, parent admodel.Identity, name string, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_organizational_units.New(c).
					CreateOrganizationalUnit(ctx, admodel.CreateOrganizationalUnitRequest{
						Parent: parent, Name: name, Options: o,
					})
				return result.Object, err
			},
			InternalUpdateRaw: func(ctx context.Context, c *adengine.Client, id admodel.Identity, changes []admodel.AttributeChange, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_organizational_units.New(c).
					UpdateOrganizationalUnit(ctx, admodel.UpdateOrganizationalUnitRequest{
						Identity: id, Changes: changes, Options: o,
					})
				return result.Object, err
			},
			InternalUpdateTyped: func(ctx context.Context, c *adengine.Client, id admodel.Identity, value string, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				result, err := adservice_organizational_units.New(c).
					UpdateOrganizationalUnit(ctx, admodel.UpdateOrganizationalUnitRequest{
						Identity:   id,
						Properties: admodel.OUProperties{DisplayName: text(value)},
						Options:    o,
					})
				return result.Object, err
			},
			InternalUnprotect: func(ctx context.Context, c *adengine.Client, id admodel.Identity, o admodel.ObjectMutationOptions) error {
				_, err := adservice_organizational_units.New(c).
					SetOrganizationalUnitProtection(ctx, id, false, o)
				return err
			},
			InternalRemove: func(ctx context.Context, c *adengine.Client, id admodel.Identity, recursive bool, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				return adservice_organizational_units.New(c).
					DeleteOrganizationalUnit(ctx, admodel.DeleteOrganizationalUnitRequest{
						Identity: id, Recursive: recursive, Options: o,
					})
			},
		},
		{
			// The generic path carries the class explicitly, which is what makes
			// schema-class-and-container observable: a container holds children,
			// so the delete boundaries apply to it as they do to the unit.
			InternalKind:         "object",
			InternalClass:        "container",
			InternalCreateCmdlet: "New-ADObject",
			InternalUpdateCmdlet: "Set-ADObject",
			InternalRemoveCmdlet: "Remove-ADObject",
			InternalCreateWithAttributes: func(ctx context.Context, c *adengine.Client, parent admodel.Identity, name string, attrs map[string][]admodel.RawValue, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				return c.CreateObject(ctx, admodel.CreateObjectRequest{
					Parent: parent, Class: "container", Name: name, Attributes: attrs, Options: o,
				})
			},
			// createWithProperties stays nil: the generic path has no typed
			// property layer, so its explicit attribute map is the instance.
			InternalContainer: true,
			InternalCreate: func(ctx context.Context, c *adengine.Client, parent admodel.Identity, name string, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				return c.CreateObject(ctx, admodel.CreateObjectRequest{
					Parent: parent, Class: "container", Name: name, Options: o,
				})
			},
			InternalUpdateRaw: func(ctx context.Context, c *adengine.Client, id admodel.Identity, changes []admodel.AttributeChange, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				return c.UpdateObject(
					ctx,
					admodel.UpdateObjectRequest{Identity: id, Changes: changes, Options: o},
				)
			},
			InternalUpdateTyped: func(ctx context.Context, c *adengine.Client, id admodel.Identity, value string, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				// The generic path has no typed property layer, so the typed
				// scenario's subject here is an explicit single-valued Set,
				// which is the documented Go replacement for -Instance.
				return c.UpdateObject(
					ctx,
					admodel.UpdateObjectRequest{Identity: id, Changes: []admodel.AttributeChange{{
						Attribute: InternalLifecycleSingle, Kind: admodel.AttributeSet,
						Values: []admodel.RawValue{admodel.NewRawValue([]byte(value))},
					}}, Options: o},
				)
			},
			InternalRemove: func(ctx context.Context, c *adengine.Client, id admodel.Identity, recursive bool, o admodel.ObjectMutationOptions) (admodel.ObjectMutationResult, error) {
				return c.DeleteObject(
					ctx,
					admodel.DeleteObjectRequest{Identity: id, Recursive: recursive, Options: o},
				)
			},
		},
	}
}

// lifecycleObservation is one class's complete record. Each field names a half
// of a scenario rather than a step of the harness, so an artifact reader can
// see which half of which scenario an incomplete run is missing.
type InternalLifecycleObservation struct {
	Kind  string `json:"kind"`
	Class string `json:"class"`

	// creation-defaults-and-readback
	CreatedVerified    bool   `json:"created_verified"`
	CreatedClass       string `json:"created_class"`
	CreatedInContainer bool   `json:"created_in_requested_container"`
	CreatedIdentity    string `json:"created_identity"`
	DuplicateRefused   bool   `json:"duplicate_name_refused"`
	DuplicateClass     string `json:"duplicate_name_error_class"`
	DuplicateWroteOnce bool   `json:"duplicate_left_one_object"`
	DuplicateDetail    string `json:"duplicate_name_detail,omitempty"`

	// attribute-update-intent
	//
	// Each half records why it failed, not only that it did. A boolean
	// artifact is unactionable: the first run of this harness reported three
	// of these false and cost two rounds of guessing at the cause.
	SetApplied    bool   `json:"set_applied"`
	SetDetail     string `json:"set_detail,omitempty"`
	AddApplied    bool   `json:"add_applied"`
	AddDetail     string `json:"add_detail,omitempty"`
	RemoveApplied bool   `json:"remove_applied"`
	RemoveDetail  string `json:"remove_detail,omitempty"`
	// A Clear is accepted but never verified by this SDK: an absent
	// attribute cannot prove emptiness, because omission can equally mean
	// denied visibility. So the two halves are recorded separately — the
	// write was accepted, and a separate read found the attribute absent —
	// along with the class the unverified outcome reports as.
	ClearAccepted          bool   `json:"clear_accepted"`
	ClearReadsAbsent       bool   `json:"clear_reads_absent"`
	ClearClass             string `json:"clear_outcome_class"`
	ClearDetail            string `json:"clear_detail,omitempty"`
	UnrelatedValueSurvived bool   `json:"unrelated_value_survived"`
	UndefinedRefused       bool   `json:"undefined_attribute_refused"`
	UndefinedClass         string `json:"undefined_attribute_error_class"`
	UndefinedWroteNothing  bool   `json:"undefined_attribute_wrote_nothing"`
	UndefinedDetail        string `json:"undefined_attribute_detail,omitempty"`

	// instance-update-semantics
	TypedApplied       bool   `json:"typed_update_applied"`
	TypedDetail        string `json:"typed_update_detail,omitempty"`
	OmittedUntouched   bool   `json:"omitted_attribute_untouched"`
	StaleVersion       string `json:"stale_version_outcome"`
	StaleVersionClass  string `json:"stale_version_error_class"`
	StaleWroteNothing  bool   `json:"stale_version_wrote_nothing"`
	ConcurrentSurvived bool   `json:"concurrent_unrelated_change_survived"`

	// object-deletion-and-reference-constraints
	DeletedAbsentAfter bool   `json:"deleted_absent_after"`
	DeleteVerified     bool   `json:"delete_verified"`
	SecondDeleteClass  string `json:"second_delete_error_class"`
	ProtectedRefused   string `json:"protected_delete_outcome,omitempty"`

	// recursive-delete-boundary; container classes only
	NonLeafRefused    bool   `json:"non_leaf_delete_refused,omitempty"`
	NonLeafClass      string `json:"non_leaf_error_class,omitempty"`
	NonLeafChildKept  bool   `json:"non_leaf_refusal_kept_the_child,omitempty"`
	RecursiveRemoved  bool   `json:"recursive_delete_removed_children,omitempty"`
	RecursiveVerified bool   `json:"recursive_delete_absent_after,omitempty"`

	AllocationsRemaining int    `json:"allocations_remaining"`
	Detail               string `json:"detail,omitempty"`
	Passed               bool   `json:"passed"`
}

// qualifies requires both halves of every scenario this class participates in.
// The container-only fields are required exactly when the class is a container,
// so a leaf is never credited with a boundary it cannot reach and a container is
// never excused from one it can.
func (o InternalLifecycleObservation) InternalQualifies(target InternalLifecycleTarget) bool {
	creation := o.CreatedVerified && o.CreatedClass == target.InternalClass &&
		o.CreatedInContainer &&
		o.CreatedIdentity != "" &&
		o.DuplicateRefused &&
		o.DuplicateClass == admodel.ClassAlreadyExists.String() &&
		o.DuplicateWroteOnce
	// The clear requirement is the documented behaviour rather than the
	// intuitive one: accepted, read back absent, and reported as uncertain
	// because this SDK will not claim to have verified an omission.
	attribute := o.SetApplied && o.AddApplied && o.RemoveApplied &&
		o.ClearAccepted && o.ClearReadsAbsent && o.ClearClass == admodel.ClassUncertain.String() &&
		o.UnrelatedValueSurvived && o.UndefinedRefused && o.UndefinedWroteNothing &&
		(o.UndefinedClass == admodel.ClassInvalidRequest.String() || o.UndefinedClass == admodel.ClassUnsupported.String())
	// A stale precondition must either be refused as a conflict or be refused
	// as unsupported by this server. Both are honest; silently applying the
	// write is not, and neither is reporting success.
	instance := o.TypedApplied && o.OmittedUntouched && o.ConcurrentSurvived &&
		o.StaleWroteNothing &&
		(o.StaleVersionClass == admodel.ClassConflict.String() || o.StaleVersionClass == admodel.ClassUnsupported.String())
	deletion := o.DeletedAbsentAfter && o.DeleteVerified &&
		o.SecondDeleteClass == admodel.ClassNotFound.String()
	if target.InternalProtectedByDefault && o.ProtectedRefused != "refused" {
		deletion = false
	}
	boundary := true
	if target.InternalContainer {
		boundary = o.NonLeafRefused && o.NonLeafChildKept &&
			(o.NonLeafClass == admodel.ClassInvalidRequest.String() || o.NonLeafClass == admodel.ClassConflict.String()) &&
			o.RecursiveRemoved && o.RecursiveVerified
	}
	return creation && attribute && instance && deletion && boundary &&
		o.AllocationsRemaining == 0
}

// lifecycleDetail renders an error for the artifact, including the LDAP status
// when one is present. A classification alone does not say which refusal the
// directory produced, and a bare message does not say which status it carried.
func InternalLifecycleDetail(err error) string {
	if err == nil {
		return ""
	}
	var ldapErr *admodel.LDAPError
	if errors.As(err, &ldapErr) {
		return fmt.Sprintf("%v [LDAP %d]", err, ldapErr.Code)
	}
	return err.Error()
}

// lifecycleWhy explains a half that did not hold: the write error if there was
// one, otherwise what the readback actually returned. Without the second case a
// value that merely came back different is indistinguishable from a refusal.
func InternalLifecycleWhy(
	writeErr error,
	values []string,
	state admodel.AttributeState,
	readErr error,
) string {
	switch {
	case writeErr != nil:
		return "write: " + InternalLifecycleDetail(writeErr)
	case readErr != nil:
		return "readback: " + InternalLifecycleDetail(readErr)
	default:
		return fmt.Sprintf("readback returned %v (state %d)", values, state)
	}
}

// lifecycleClass reports the error class by name, so the artifact records which
// classification the directory produced rather than only that it refused. A
// refusal for the wrong reason is a different observation and must not pass.
func InternalLifecycleClass(err error) string {
	if err == nil {
		return ""
	}
	return admodel.Classify(err).String()
}

// lifecycleValues reads one attribute's current values as text. It distinguishes
// absent from unloaded, because "the attribute is not there" and "we did not ask
// for it" are the two readings a clear must be able to tell apart.
func InternalLifecycleValues(
	ctx context.Context,
	c *adengine.Client,
	id admodel.Identity,
	attribute string,
) ([]string, admodel.AttributeState, error) {
	observed, err := c.ResolveIdentity(
		ctx,
		id,
		admodel.ResolveIdentityOptions{Properties: []string{attribute}},
	)
	if err != nil {
		return nil, admodel.AttributeUnloaded, err
	}
	if observed.Object == nil {
		return nil, admodel.AttributeUnloaded, admodel.ErrDirectoryObjectNotFound
	}
	raw, state := observed.Object.Attribute(attribute)
	values := make([]string, 0, len(raw))
	for _, value := range raw {
		values = append(values, string(value))
	}
	slices.Sort(values)
	return values, state, nil
}

func InternalLifecycleAbsent(ctx context.Context, c *adengine.Client, id admodel.Identity) bool {
	_, err := c.ResolveIdentity(
		ctx,
		id,
		admodel.ResolveIdentityOptions{Properties: []string{"objectGUID"}},
	)
	return admodel.IsNotFound(err)
}

func InternalLifecycleRawValues(values ...string) []admodel.RawValue {
	raw := make([]admodel.RawValue, 0, len(values))
	for _, value := range values {
		raw = append(raw, admodel.NewRawValue([]byte(value)))
	}
	return raw
}

// The outer harness supplies the endpoint and the write authorization only
// inside an owned run. This test mutates the directory: it creates an
// organizational unit and fixtures beneath it, and removes them. Ordinary go
// test invocations skip it.
//
// It qualifies creation-defaults-and-readback, attribute-update-intent,
// instance-update-semantics, object-deletion-and-reference-constraints and
// recursive-delete-boundary across the five classes a caller would model as
// resources, recording both halves of each.
func TestDirectoryLifecycleSweepLab(t *testing.T) {
	endpoint := os.Getenv("ADSDK_LIFECYCLE_ENDPOINT")
	if endpoint == "" {
		t.Skip("requires the opt-in isolated directory lifecycle harness")
	}
	if os.Getenv("ADSDK_LIFECYCLE_ALLOW_WRITES") != "yes" {
		t.Fatal("this harness mutates the directory and requires explicit write authorization")
	}
	resultPath := os.Getenv("ADSDK_LIFECYCLE_RESULT")
	runID := os.Getenv("ADSDK_LIFECYCLE_RUN_ID")
	if resultPath == "" || runID == "" {
		t.Fatal("an endpoint, a run identity and a fresh result path are required")
	}

	artifact := struct {
		SchemaVersion       int                            `json:"schema_version"`
		Scope               string                         `json:"scope"`
		RunID               string                         `json:"run_id"`
		Endpoint            string                         `json:"endpoint"`
		RuntimeOS           string                         `json:"runtime_os"`
		RuntimeArchitecture string                         `json:"runtime_architecture"`
		Started             time.Time                      `json:"started"`
		Finished            time.Time                      `json:"finished"`
		Passed              bool                           `json:"passed"`
		FullTicketComplete  bool                           `json:"full_ticket_complete"`
		FailureStage        string                         `json:"failure_stage,omitempty"`
		FixtureRoot         string                         `json:"fixture_root"`
		FixtureRootRemoved  bool                           `json:"fixture_root_removed"`
		Operations          []InternalLifecycleObservation `json:"operations"`
	}{
		SchemaVersion: 1, Scope: "directory-mutation-lifecycle", RunID: runID,
		Endpoint: endpoint, RuntimeOS: runtime.GOOS, RuntimeArchitecture: runtime.GOARCH,
		Started: time.Now().UTC(), Operations: []InternalLifecycleObservation{},
	}
	stage := "start"
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
			t.Error("cannot encode lifecycle artifact")
			return
		}
		file, err := os.OpenFile(resultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Error("cannot create fresh lifecycle artifact")
			return
		}
		_, writeErr := file.Write(append(data, '\n'))
		if closeErr := file.Close(); writeErr != nil || closeErr != nil {
			t.Error("cannot finish lifecycle artifact")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	client, err := adengine.Dial(
		ctx,
		admodel.Config{
			Endpoint: admodel.Endpoint{Host: endpoint, Port: 389},
			Timeout:  60 * time.Second,
		},
	)
	if err != nil {
		t.Fatal("native dial failed")
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Error("the client did not close cleanly")
		}
	}()

	stage = "default-naming-context"
	root, err := client.RootDSE(ctx, admodel.RootDSEOptions{})
	if err != nil || root.DefaultNamingContext == nil || *root.DefaultNamingContext == "" {
		t.Fatal("the connection did not report a default naming context")
	}
	domain := *root.DefaultNamingContext

	// One fixture root for the whole run, named after the run so a leftover is
	// attributable. Creating it is also the first proof that a create works at
	// all; if it fails there is nothing to qualify.
	stage = "fixture-root"
	rootName := "sdk-lifecycle-" + runID
	domainIdentity, err := admodel.IdentityByDN(domain)
	if err != nil {
		t.Fatal("the default naming context is not a usable identity")
	}
	// An organizational unit, not a container: an organizationalUnit cannot be
	// created inside a container at all — the directory refuses it with LDAP 64
	// — so a container root would make the unit's own lifecycle unobservable.
	// Created unprotected, which #147 made possible.
	rootResult, rootErr := adservice_organizational_units.New(client).
		CreateOrganizationalUnit(ctx, admodel.CreateOrganizationalUnitRequest{
			Parent: domainIdentity, Name: rootName,
			ProtectedFromAccidentalDeletion: new(bool), // explicit false: this is a fixture
		})

	// Cleanup is installed from whatever the create reported, before any
	// decision about whether it succeeded. A create that fails after the object
	// was written is exactly the uncertain case, and an earlier version of this
	// harness called t.Fatalf on it and so never installed cleanup — leaving a
	// fixture root behind, which the collector's independent check caught.
	// Anything with a GUID is removable and must be removed.
	if rootResult.Object.TargetGUID != nil {
		artifact.FixtureRoot = rootResult.Object.TargetDN
		root := admodel.InternalObjectGUIDIdentity(*rootResult.Object.TargetGUID)
		defer func() {
			removal, removeErr := adservice_organizational_units.New(client).
				DeleteOrganizationalUnit(ctx, admodel.DeleteOrganizationalUnitRequest{
					Identity: root, Recursive: true,
				})
			absent := removal.AbsentAfter && InternalLifecycleAbsent(ctx, client, root)
			artifact.FixtureRootRemoved = removeErr == nil && absent
			if !artifact.FixtureRootRemoved {
				t.Errorf("the fixture root was not proved removed: err=%v absentAfter=%v",
					removeErr, removal.AbsentAfter)
			}
		}()
	}
	if rootErr != nil || rootResult.Object.TargetGUID == nil {
		t.Fatalf("cannot create the fixture root: %v", rootErr)
	}
	fixtureRoot := admodel.InternalObjectGUIDIdentity(*rootResult.Object.TargetGUID)

	stage = "lifecycle-sweep"
	for _, target := range InternalLifecycleTargets() {
		o := InternalLifecycleObservation{Kind: target.InternalKind, Class: target.InternalClass}
		var counts InternalSearchNativeCounts
		(*adengine.InternalClientSessionPointer(client)).(*adengine.InternalLdapSession).InternalApi = InternalCountedSearchAPI(
			&counts,
		)

		// Non-ASCII and a supplementary-plane character, carried over from the
		// identity qualification, so naming is exercised rather than assumed.
		name := "sdk" + strings.ReplaceAll(target.InternalKind, " ", "") + "é\U0001f511"
		// A computer's name becomes a sAMAccountName, which is bounded and
		// must not carry those characters, so that one class uses plain text.
		if target.InternalKind == "computer" {
			name = "SDKLIFE" + strconv.Itoa(len(artifact.Operations))
		}
		observe := admodel.ObjectMutationOptions{
			Properties: []string{
				InternalLifecycleMultiValued,
				InternalLifecycleSingle,
				"objectClass",
			},
		}

		// --- creation-defaults-and-readback -----------------------------
		created, createErr := target.InternalCreate(ctx, client, fixtureRoot, name, observe)
		if createErr != nil || created.TargetGUID == nil {
			o.Detail = fmt.Sprintf("create: %v", createErr)
			o.Passed = false
			fail(
				"%s: create failed, so nothing downstream is observable: %v",
				target.InternalKind,
				createErr,
			)
			artifact.Operations = append(artifact.Operations, o)
			continue
		}
		subject := admodel.InternalObjectGUIDIdentity(*created.TargetGUID)
		o.CreatedVerified = created.Verified && created.ReadbackComplete
		o.CreatedIdentity, _ = func() (string, error) {
			text, err := subject.MarshalText()
			return string(text), err
		}()
		o.CreatedInContainer = strings.HasSuffix(strings.ToLower(created.TargetDN),
			strings.ToLower(","+artifact.FixtureRoot))
		if created.After != nil {
			if classes, state := created.After.Attribute(
				"objectClass",
			); state == admodel.AttributePresent &&
				len(classes) > 0 {
				// The structural class is the last value; the earlier ones are
				// the inherited chain.
				o.CreatedClass = string(classes[len(classes)-1])
			}
		}

		// The same name again, in the same container. Exactly one object must
		// exist afterwards, so the refusal is proved not to have written.
		_, duplicateErr := target.InternalCreate(ctx, client, fixtureRoot, name, observe)
		o.DuplicateRefused = duplicateErr != nil
		o.DuplicateClass = InternalLifecycleClass(duplicateErr)
		o.DuplicateDetail = InternalLifecycleDetail(duplicateErr)
		o.DuplicateWroteOnce = !InternalLifecycleAbsent(ctx, client, subject)

		// --- attribute-update-intent ------------------------------------
		// Set two values, add a third, remove one, and clear the rest. An
		// unrelated single-valued attribute is written first and checked at the
		// end, so "unrelated values survive" is observed rather than asserted.
		const unrelated = "sdk-unrelated-value"
		if _, err := target.InternalUpdateRaw(ctx, client, subject, []admodel.AttributeChange{
			{
				Attribute: InternalLifecycleSingle,
				Kind:      admodel.AttributeSet,
				Values:    InternalLifecycleRawValues(unrelated),
			},
		}, observe); err != nil {
			o.Detail = fmt.Sprintf("seed unrelated: %v", err)
		}

		_, setErr := target.InternalUpdateRaw(ctx, client, subject, []admodel.AttributeChange{
			{
				Attribute: InternalLifecycleMultiValued,
				Kind:      admodel.AttributeSet,
				Values:    InternalLifecycleRawValues("alpha", "beta"),
			},
		}, observe)
		values, setState, setReadErr := InternalLifecycleValues(
			ctx,
			client,
			subject,
			InternalLifecycleMultiValued,
		)
		o.SetApplied = setErr == nil && slices.Equal(values, []string{"alpha", "beta"})
		if !o.SetApplied {
			o.SetDetail = InternalLifecycleWhy(setErr, values, setState, setReadErr)
		}

		_, addErr := target.InternalUpdateRaw(ctx, client, subject, []admodel.AttributeChange{
			{
				Attribute: InternalLifecycleMultiValued,
				Kind:      admodel.AttributeAddValues,
				Values:    InternalLifecycleRawValues("gamma"),
			},
		}, observe)
		values, addState, addReadErr := InternalLifecycleValues(
			ctx,
			client,
			subject,
			InternalLifecycleMultiValued,
		)
		o.AddApplied = addErr == nil && slices.Equal(values, []string{"alpha", "beta", "gamma"})
		if !o.AddApplied {
			o.AddDetail = InternalLifecycleWhy(addErr, values, addState, addReadErr)
		}

		_, removeErr := target.InternalUpdateRaw(ctx, client, subject, []admodel.AttributeChange{
			{
				Attribute: InternalLifecycleMultiValued,
				Kind:      admodel.AttributeRemoveValues,
				Values:    InternalLifecycleRawValues("beta"),
			},
		}, observe)
		values, removeState, removeReadErr := InternalLifecycleValues(
			ctx,
			client,
			subject,
			InternalLifecycleMultiValued,
		)
		o.RemoveApplied = removeErr == nil && slices.Equal(values, []string{"alpha", "gamma"})
		if !o.RemoveApplied {
			o.RemoveDetail = InternalLifecycleWhy(removeErr, values, removeState, removeReadErr)
		}

		cleared, clearErr := target.InternalUpdateRaw(
			ctx,
			client,
			subject,
			[]admodel.AttributeChange{{
				Attribute: InternalLifecycleMultiValued, Kind: admodel.AttributeClear,
			}},
			observe,
		)
		// This SDK never verifies a clear, by design: an absent attribute
		// cannot prove emptiness, because omission can equally mean denied
		// visibility. So the write is accepted and the call still reports
		// ErrObjectVerification. Both are recorded, and a separate read is what
		// establishes the attribute actually went away — read as absent, not as
		// present-and-empty, and not as unloaded, since it was requested.
		o.ClearAccepted = cleared.State == admodel.ObjectWriteAccepted
		o.ClearClass = InternalLifecycleClass(clearErr)
		o.ClearDetail = InternalLifecycleDetail(clearErr)
		values, state, _ := InternalLifecycleValues(
			ctx,
			client,
			subject,
			InternalLifecycleMultiValued,
		)
		o.ClearReadsAbsent = state == admodel.AttributeAbsent && len(values) == 0
		if clearErr != nil && !errors.Is(clearErr, admodel.ErrObjectVerification) {
			o.Detail = strings.TrimSpace(o.Detail + " clear: " + clearErr.Error())
		}

		// An attribute the schema does not define. The refusal must come from
		// the directory's schema rather than from a guess, and must write
		// nothing — including not the valid change submitted alongside it.
		_, undefinedErr := target.InternalUpdateRaw(ctx, client, subject, []admodel.AttributeChange{
			{
				Attribute: InternalLifecycleUndefined,
				Kind:      admodel.AttributeSet,
				Values:    InternalLifecycleRawValues("x"),
			},
			{
				Attribute: InternalLifecycleMultiValued,
				Kind:      admodel.AttributeSet,
				Values:    InternalLifecycleRawValues("must-not-land"),
			},
		}, observe)
		o.UndefinedRefused = undefinedErr != nil
		o.UndefinedClass = InternalLifecycleClass(undefinedErr)
		o.UndefinedDetail = InternalLifecycleDetail(undefinedErr)
		values, state, _ = InternalLifecycleValues(
			ctx,
			client,
			subject,
			InternalLifecycleMultiValued,
		)
		o.UndefinedWroteNothing = state == admodel.AttributeAbsent &&
			!slices.Contains(values, "must-not-land")

		single, _, _ := InternalLifecycleValues(ctx, client, subject, InternalLifecycleSingle)
		o.UnrelatedValueSurvived = slices.Contains(single, unrelated)

		// --- instance-update-semantics ----------------------------------
		// A typed property update must change its own attribute and leave the
		// one the raw changes were using alone.
		const typed = "sdk-typed-display-name"
		typedResult, typedErr := target.InternalUpdateTyped(ctx, client, subject, typed, observe)
		single, _, _ = InternalLifecycleValues(ctx, client, subject, InternalLifecycleSingle)
		o.TypedApplied = typedErr == nil && typedResult.Verified && slices.Contains(single, typed)
		if !o.TypedApplied {
			o.TypedDetail = InternalLifecycleWhy(typedErr, single, admodel.AttributePresent, nil)
		}
		_, omittedState, _ := InternalLifecycleValues(
			ctx,
			client,
			subject,
			InternalLifecycleMultiValued,
		)
		o.OmittedUntouched = omittedState == admodel.AttributeAbsent

		// A stale precondition. The version is read, the object is then changed
		// by another write, and the stale version is submitted afterwards.
		version, versionErr := InternalLifecycleVersion(ctx, client, subject)
		if versionErr != nil {
			o.StaleVersion = "version unreadable: " + versionErr.Error()
		} else {
			if _, err := target.InternalUpdateRaw(ctx, client, subject, []admodel.AttributeChange{
				{
					Attribute: InternalLifecycleMultiValued,
					Kind:      admodel.AttributeSet,
					Values:    InternalLifecycleRawValues("bumped"),
				},
			}, observe); err != nil {
				o.Detail = strings.TrimSpace(o.Detail + " bump: " + err.Error())
			}
			stale := observe
			stale.ExpectedVersion = &version
			_, staleErr := target.InternalUpdateRaw(
				ctx,
				client,
				subject,
				[]admodel.AttributeChange{
					{
						Attribute: InternalLifecycleMultiValued,
						Kind:      admodel.AttributeSet,
						Values:    InternalLifecycleRawValues("stale-must-not-land"),
					},
				},
				stale,
			)
			o.StaleVersionClass = InternalLifecycleClass(staleErr)
			switch {
			case staleErr == nil:
				o.StaleVersion = "applied"
			case errors.Is(staleErr, admodel.ErrObjectConcurrency):
				o.StaleVersion = "refused as a precondition failure"
			case errors.Is(staleErr, admodel.ErrObjectControlUnsupported):
				o.StaleVersion = "refused: the server does not enforce the assertion"
			default:
				o.StaleVersion = "refused: " + staleErr.Error()
			}
			values, _, _ = InternalLifecycleValues(
				ctx,
				client,
				subject,
				InternalLifecycleMultiValued,
			)
			o.StaleWroteNothing = !slices.Contains(values, "stale-must-not-land")
			o.ConcurrentSurvived = slices.Contains(values, "bumped")
		}

		// --- recursive-delete-boundary ----------------------------------
		if target.InternalContainer {
			// A class this SDK protects on creation cannot be deleted at all
			// until that protection is lifted, so the boundary has to be
			// reached first or the refusal observed below would be the
			// protection's and not the non-leaf rule's. The protection itself
			// is observed separately, on the deletion fixture.
			if target.InternalProtectedByDefault && target.InternalUnprotect != nil {
				if err := target.InternalUnprotect(
					ctx,
					client,
					subject,
					admodel.ObjectMutationOptions{},
				); err != nil {
					o.Detail = strings.TrimSpace(o.Detail + " unprotect subject: " + err.Error())
				}
			}
			childResult, childErr := client.CreateObject(ctx, admodel.CreateObjectRequest{
				Parent: subject, Class: "container", Name: "sdk-child",
			})
			if childErr != nil || childResult.TargetGUID == nil {
				o.Detail = strings.TrimSpace(o.Detail + " child: " + fmt.Sprint(childErr))
			} else {
				child := admodel.InternalObjectGUIDIdentity(*childResult.TargetGUID)
				_, nonLeafErr := target.InternalRemove(
					ctx,
					client,
					subject,
					false,
					admodel.ObjectMutationOptions{},
				)
				o.NonLeafRefused = nonLeafErr != nil
				o.NonLeafClass = InternalLifecycleClass(nonLeafErr)
				o.NonLeafChildKept = !InternalLifecycleAbsent(ctx, client, child) &&
					!InternalLifecycleAbsent(ctx, client, subject)

				recursive, recursiveErr := target.InternalRemove(
					ctx,
					client,
					subject,
					true,
					admodel.ObjectMutationOptions{},
				)
				o.RecursiveRemoved = recursiveErr == nil &&
					InternalLifecycleAbsent(ctx, client, child)
				o.RecursiveVerified = recursive.AbsentAfter &&
					InternalLifecycleAbsent(ctx, client, subject)
			}
		}

		// --- object-deletion-and-reference-constraints ------------------
		// A container class has already been deleted recursively above, so the
		// deletion scenario uses a second, leaf fixture of the same class. That
		// keeps the two boundaries from standing in for each other.
		deleteName := name + "-del"
		if target.InternalKind == "computer" {
			deleteName = name + "D"
		}
		victim, victimErr := target.InternalCreate(ctx, client, fixtureRoot, deleteName, observe)
		switch {
		case victimErr != nil || victim.TargetGUID == nil:
			o.Detail = strings.TrimSpace(o.Detail + " deletion fixture: " + fmt.Sprint(victimErr))
		default:
			id := admodel.InternalObjectGUIDIdentity(*victim.TargetGUID)
			if target.InternalProtectedByDefault {
				// Created protected by this SDK without being asked, so the
				// first delete must be refused. That refusal is the scenario's
				// failure half: a reference constraint the directory holds.
				_, protectedErr := target.InternalRemove(
					ctx,
					client,
					id,
					false,
					admodel.ObjectMutationOptions{},
				)
				if protectedErr != nil && !InternalLifecycleAbsent(ctx, client, id) {
					o.ProtectedRefused = "refused"
				} else {
					o.ProtectedRefused = "not refused"
				}
				if target.InternalUnprotect != nil {
					if err := target.InternalUnprotect(
						ctx,
						client,
						id,
						admodel.ObjectMutationOptions{},
					); err != nil {
						o.Detail = strings.TrimSpace(o.Detail + " unprotect: " + err.Error())
					}
				}
			}
			removal, removalErr := target.InternalRemove(
				ctx,
				client,
				id,
				false,
				admodel.ObjectMutationOptions{},
			)
			o.DeletedAbsentAfter = removalErr == nil && removal.AbsentAfter &&
				InternalLifecycleAbsent(ctx, client, id)
			o.DeleteVerified = removal.Verified
			// Deleting it again must report absence, not an error a caller
			// cannot classify. A provider converges on this every time it
			// retries a destroy.
			_, secondErr := target.InternalRemove(
				ctx,
				client,
				id,
				false,
				admodel.ObjectMutationOptions{},
			)
			o.SecondDeleteClass = InternalLifecycleClass(secondErr)
		}

		o.AllocationsRemaining = InternalSweepAllocations(counts)
		o.Passed = o.InternalQualifies(target)
		if !o.Passed {
			fail("%s: lifecycle observation incomplete: %+v", target.InternalKind, o)
		}
		artifact.Operations = append(artifact.Operations, o)
	}

	if !t.Failed() {
		stage = "complete"
	}
	t.Logf(
		"mutation lifecycle sweep over %d classes on %s; full ticket qualification remains incomplete",
		len(artifact.Operations),
		endpoint,
	)
}

// lifecycleVersion reads the precondition an optimistic update needs. It is
// separate because uSNChanged is a counter the server owns: reading it through
// the typed value layer is the only way to be sure the harness is asserting the
// same number the SDK would send.
func InternalLifecycleVersion(
	ctx context.Context,
	c *adengine.Client,
	id admodel.Identity,
) (admodel.ObjectVersion, error) {
	var version admodel.ObjectVersion
	observed, err := c.ResolveIdentity(ctx, id, admodel.ResolveIdentityOptions{
		Properties: []string{"objectGUID", "uSNChanged"},
	})
	if err != nil {
		return version, err
	}
	if observed.Object == nil {
		return version, admodel.ErrDirectoryObjectNotFound
	}
	guidValue, err := observed.Object.Values("objectGUID").Single()
	if err != nil {
		return version, err
	}
	guid, err := guidValue.GUID()
	if err != nil {
		return version, err
	}
	usnValue, err := observed.Object.Values("uSNChanged").Single()
	if err != nil {
		return version, err
	}
	// uSNChanged is an LDAP LargeInteger, so the typed layer reads it signed,
	// while ObjectVersion carries it unsigned. A negative value is a server
	// anomaly rather than a counter, and must not wrap into a huge uint64.
	usn, err := usnValue.Int64()
	if err != nil {
		return version, err
	}
	if usn < 0 {
		return version, fmt.Errorf("%w: uSNChanged is negative", admodel.ErrInvalidResult)
	}
	return admodel.ObjectVersion{Source: observed.Source, GUID: guid, USNChanged: uint64(usn)}, nil
}

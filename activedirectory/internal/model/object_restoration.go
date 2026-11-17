package model

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

const (
	InternalObjectShowDeletedControl          = "1.2.840.113556.1.4.417"
	InternalObjectShowRecycledControl         = "1.2.840.113556.1.4.2064"
	InternalObjectShowDeactivatedLinksControl = "1.2.840.113556.1.4.2065"
)

var (
	ErrInvalidObjectRestore = errors.New("invalid directory object restoration request")
	ErrObjectRestoreFeature = errors.New(
		"restoration requires positively observed Recycle Bin enablement",
	)
	ErrObjectNotRestorable = errors.New(
		"observed object is not eligible for Recycle Bin restoration",
	)
	ErrDeletedObjectUnavailable = errors.New(
		"deleted object was not visible on this endpoint; absence does not establish expiration",
	)
)

type DeletedObjectState uint8

const (
	DeletedStateUnknown DeletedObjectState = iota
	DeletedStateDeleted
	DeletedStateRecycled
	DeletedStateTombstone
	DeletedStateProtected
)

// DeletedObject describes an observation, not a promise that restoration will
// succeed. Omitted metadata is distinct from false. Recycled objects cannot be
// restored through Recycle Bin. An absent object cannot be distinguished from
// expired/garbage-collected, invisible, or never-existing by this LDAP view.
type DeletedObject struct {
	GUID                          *GUID
	State                         DeletedObjectState
	IsDeleted, IsRecycled         *bool
	LastKnownParent, LastKnownRDN *string
	Raw                           Object
	Error                         error
}

// ObjectRestorationCapabilities retains the connected DSA's forward feature
// links and resolved feature objects. Nil means unknown, including omitted or
// ranged links; false is used only for a complete returned list with no match.
type ObjectRestorationCapabilities struct {
	RecycleBinEnabled *bool
	Observation       DirectoryObservation
	Error             error
}

type ObjectRestoreMode uint8

const (
	// RestoreWithRecycleBin requires positively observed feature enablement.
	RestoreWithRecycleBin ObjectRestoreMode = iota
	// RestoreLegacyTombstone explicitly permits reanimation without feature
	// proof. Stripped attributes/links cannot be recovered by this operation.
	RestoreLegacyTombstone
)

type DeletedObjectQuery struct {
	Search                  SearchOptions
	IncludeRecycled         bool
	IncludeDeactivatedLinks bool
}

type DeletedObjectsResult struct {
	Source       Endpoint
	Partition    string
	Objects      []DeletedObject
	Observation  SearchResult
	Capabilities ObjectRestorationCapabilities
	Complete     bool
}

// RestoreObjectRequest restores one object, never a subtree. Identity accepts
// the current deleted DN or GUID. NewName is a literal RDN value; nil selects
// msDS-LastKnownRDN. Zero TargetParent selects lastKnownParent. The selected
// parent must exist in the same naming context. Default mode requires Recycle
// Bin. Legacy mode permits lossy reanimation and explicit replacement Attributes
// for stripped mandatory values. No mode enables directory features.
type RestoreObjectRequest struct {
	Identity     Identity
	NewName      *string
	TargetParent Identity
	Mode         ObjectRestoreMode
	// Attributes is available only in explicit legacy mode. Values are
	// replacements in the same Modify, never guessed from an incomplete row.
	// Identity, deletion metadata and the naming attribute are reserved.
	Attributes map[string][]RawValue
	Options    ObjectMutationOptions
}

type ObjectRestorationResult struct {
	Mode         ObjectRestoreMode
	Deleted      *DeletedObject
	Capabilities ObjectRestorationCapabilities
	Parent       IdentityResult
	Mutation     ObjectMutationResult
}

func InternalRestorationProperties(extra []string) []string {
	return append(
		slices.Clone(extra),
		"objectGUID",
		"objectClass",
		"name",
		"uSNChanged",
		"isDeleted",
		"isRecycled",
		"lastKnownParent",
		"msDS-LastKnownRDN",
		"systemFlags",
		"instanceType",
	)
}

func InternalRestorationControls(
	root RootDSE,
	recycled, links bool,
) ([]InternalLdapWriteControl, error) {
	oid := InternalObjectShowDeletedControl
	if recycled {
		oid = InternalObjectShowRecycledControl
	}
	controls := []InternalLdapWriteControl{{InternalOid: oid, InternalCritical: true}}
	if links {
		controls = append(
			controls,
			InternalLdapWriteControl{
				InternalOid:      InternalObjectShowDeactivatedLinksControl,
				InternalCritical: true,
			},
		)
	}
	for _, control := range controls {
		if !slices.Contains(root.SupportedControls, control.InternalOid) {
			return nil, fmt.Errorf("%w: %s", ErrObjectControlUnsupported, control.InternalOid)
		}
	}
	return controls, nil
}

func InternalRestorationRoot(
	ctx context.Context,
	session InternalDirectorySession,
	endpoint Endpoint,
) (RootDSE, error) {
	root, err := InternalReadIdentityRoot(ctx, session)
	if err != nil {
		return root, err
	}
	if root.Capabilities().Type == DirectoryUnknown {
		return root, ErrUnsupportedDirectory
	}
	if root.Capabilities().Type == DirectoryADDS &&
		(endpoint.Port == 3268 || endpoint.Port == 3269) {
		return root, ErrObjectWriteTarget
	}
	return root, nil
}

func InternalRestorationFeatureState(
	ctx context.Context,
	session InternalDirectorySession,
	config Config,
	root RootDSE,
) (result ObjectRestorationCapabilities, err error) {
	defer func() { result.Error = err }()
	result.Observation.Source = config.Endpoint
	result.Observation.RootDSE = root
	if root.DSServiceName == nil || root.ConfigurationNamingContext == nil {
		return result, ErrIncompleteResult
	}
	identity, err := IdentityByDN(*root.DSServiceName)
	if err != nil {
		return result, err
	}
	scope, err := InternalResolveIdentitySession(
		ctx,
		session,
		config,
		root,
		identity,
		ResolveIdentityOptions{
			Partition:  *root.ConfigurationNamingContext,
			Properties: []string{"msDS-EnabledFeature"},
		},
	)
	result.Observation.Objects = append(result.Observation.Objects, scope.Candidates...)
	if err != nil {
		return result, err
	}
	links := scope.Object.Values("msDS-EnabledFeature")
	if links.State != AttributePresent || len(links.Values) == 0 {
		return result, ErrAttributeUnavailable
	}
	// Scope lists are normally small. A malformed/unexpectedly large response
	// remains raw evidence, not an unbounded series of linked object reads.
	if len(links.Values) > 256 {
		return result, ErrIncompleteResult
	}
	wanted, _ := ParseGUID(OptionalFeatureRecycleBinGUID)
	enabled := false
	for _, link := range links.Values {
		dn, readErr := link.Text()
		if readErr != nil {
			return result, readErr
		}
		featureIdentity, readErr := IdentityByDN(dn)
		if readErr != nil {
			return result, readErr
		}
		feature, readErr := InternalResolveIdentitySession(
			ctx,
			session,
			config,
			root,
			featureIdentity,
			ResolveIdentityOptions{
				Partition:  *root.ConfigurationNamingContext,
				Properties: []string{"msDS-OptionalFeatureGUID"},
			},
		)
		result.Observation.Objects = append(result.Observation.Objects, feature.Candidates...)
		if readErr != nil {
			return result, readErr
		}
		value, readErr := feature.Object.Values("msDS-OptionalFeatureGUID").Single()
		if readErr != nil {
			return result, readErr
		}
		guid, readErr := value.GUID()
		if readErr != nil {
			return result, readErr
		}
		enabled = enabled || guid == wanted
	}
	result.RecycleBinEnabled = &enabled
	result.Observation.Complete = true
	return result, nil
}

func InternalDecodeDeletedObject(
	object Object,
	enabled *bool,
	excludesRecycled bool,
) DeletedObject {
	result := DeletedObject{Raw: object}
	value, err := object.Values("objectGUID").Single()
	if err == nil {
		var guid GUID
		guid, err = value.GUID()
		if err == nil {
			result.GUID = &guid
		}
	}
	result.Error = errors.Join(result.Error, err)
	optionalBool := func(attribute string) (*bool, error) {
		values := object.Values(attribute)
		if values.State == AttributeAbsent {
			return nil, nil
		}
		value, err := values.Single()
		if err != nil {
			return nil, err
		}
		parsed, err := value.Bool()
		if err != nil {
			return nil, err
		}
		return &parsed, nil
	}
	result.IsDeleted, err = optionalBool("isDeleted")
	result.Error = errors.Join(result.Error, err)
	result.IsRecycled, err = optionalBool("isRecycled")
	result.Error = errors.Join(result.Error, err)
	optionalText := func(attribute string) (*string, error) {
		values := object.Values(attribute)
		if values.State == AttributeAbsent {
			return nil, nil
		}
		value, err := values.Single()
		if err != nil {
			return nil, err
		}
		text, err := value.Text()
		if err != nil {
			return nil, err
		}
		return &text, nil
	}
	result.LastKnownParent, err = optionalText("lastKnownParent")
	result.Error = errors.Join(result.Error, err)
	result.LastKnownRDN, err = optionalText("msDS-LastKnownRDN")
	result.Error = errors.Join(result.Error, err)
	if result.IsDeleted == nil || !*result.IsDeleted {
		result.Error = errors.Join(result.Error, ErrObjectNotRestorable)
		return result
	}
	if enabled != nil {
		if !*enabled {
			result.State = DeletedStateTombstone
		} else if result.IsRecycled != nil && *result.IsRecycled {
			result.State = DeletedStateRecycled
		} else if result.IsRecycled != nil || excludesRecycled {
			result.State = DeletedStateDeleted
		}
	} else if excludesRecycled && result.IsRecycled != nil && *result.IsRecycled {
		// SHOW_DELETED excludes actual recycled-objects. A returned TRUE
		// value identifies a legacy tombstone even when feature links are hidden.
		result.State = DeletedStateTombstone
	}
	flags := object.Values("systemFlags")
	if flags.State != AttributeAbsent {
		value, err := flags.Single()
		if err == nil {
			var mask Flags32
			mask, err = value.Flags32()
			if err == nil && mask.Has(0x80000000) {
				result.State = DeletedStateProtected
			}
		}
		result.Error = errors.Join(result.Error, err)
	}
	return result
}

func InternalRestoreAttributeModifications(
	attributes map[string][]RawValue,
) ([]InternalLdapAttributeModification, error) {
	mods, err := InternalCreateObjectAttributes(attributes)
	if err != nil {
		return nil, errors.Join(ErrInvalidObjectRestore, err)
	}
	for i := range mods {
		switch strings.ToLower(mods[i].InternalAttribute) {
		case "isdeleted",
			"isrecycled",
			"lastknownparent",
			"msds-lastknownrdn",
			"instancetype",
			"systemflags":
			return nil, fmt.Errorf(
				"%w: reserved restoration attribute %s",
				ErrInvalidObjectRestore,
				mods[i].InternalAttribute,
			)
		}
		mods[i].InternalOperation = 2
	}
	return mods, nil
}

func InternalValidateRestorationObject(object Object, partition string, root RootDSE) error {
	dn, err := InternalParseIdentityDN(object.DistinguishedName)
	if err != nil {
		return err
	}
	nc, err := InternalParseIdentityDN(partition)
	if err != nil {
		return err
	}
	if InternalSameIdentityDN(dn, nc) {
		return ErrObjectNotRestorable
	}
	if root.SchemaNamingContext != nil {
		schema, err := InternalParseIdentityDN(*root.SchemaNamingContext)
		if err != nil {
			return err
		}
		if InternalSameIdentityDN(nc, schema) {
			return ErrObjectNotRestorable
		}
	}
	classes := object.Values("objectClass")
	if classes.State != AttributePresent || len(classes.Values) == 0 {
		return ErrAttributeUnavailable
	}
	for _, value := range classes.Values {
		class, err := value.Text()
		if err != nil {
			return err
		}
		if strings.EqualFold(class, "classSchema") || strings.EqualFold(class, "attributeSchema") {
			return ErrObjectNotRestorable
		}
	}
	if flags := object.Values("instanceType"); flags.State != AttributeAbsent {
		value, err := flags.Single()
		if err != nil {
			return err
		}
		mask, err := value.Flags32()
		if err != nil {
			return err
		}
		if mask.Has(1) {
			return ErrObjectNotRestorable
		}
	}
	return nil
}

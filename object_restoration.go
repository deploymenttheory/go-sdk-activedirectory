package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

const (
	objectShowDeletedControl          = "1.2.840.113556.1.4.417"
	objectShowRecycledControl         = "1.2.840.113556.1.4.2064"
	objectShowDeactivatedLinksControl = "1.2.840.113556.1.4.2065"
)

var (
	ErrInvalidObjectRestore     = errors.New("invalid directory object restoration request")
	ErrObjectRestoreFeature     = errors.New("restoration requires positively observed Recycle Bin enablement")
	ErrObjectNotRestorable      = errors.New("observed object is not eligible for Recycle Bin restoration")
	ErrDeletedObjectUnavailable = errors.New("deleted object was not visible on this endpoint; absence does not establish expiration")
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

func restorationProperties(extra []string) []string {
	return append(slices.Clone(extra), "objectGUID", "objectClass", "name", "uSNChanged", "isDeleted", "isRecycled", "lastKnownParent", "msDS-LastKnownRDN", "systemFlags", "instanceType")
}

func restorationControls(root RootDSE, recycled, links bool) ([]ldapWriteControl, error) {
	oid := objectShowDeletedControl
	if recycled {
		oid = objectShowRecycledControl
	}
	controls := []ldapWriteControl{{oid: oid, critical: true}}
	if links {
		controls = append(controls, ldapWriteControl{oid: objectShowDeactivatedLinksControl, critical: true})
	}
	for _, control := range controls {
		if !slices.Contains(root.SupportedControls, control.oid) {
			return nil, fmt.Errorf("%w: %s", ErrObjectControlUnsupported, control.oid)
		}
	}
	return controls, nil
}

func restorationRoot(ctx context.Context, session directorySession, endpoint Endpoint) (RootDSE, error) {
	root, err := readIdentityRoot(ctx, session)
	if err != nil {
		return root, err
	}
	if root.Capabilities().Type == DirectoryUnknown {
		return root, ErrUnsupportedDirectory
	}
	if root.Capabilities().Type == DirectoryADDS && (endpoint.Port == 3268 || endpoint.Port == 3269) {
		return root, ErrObjectWriteTarget
	}
	return root, nil
}

func restorationFeatureState(ctx context.Context, session directorySession, config Config, root RootDSE) (result ObjectRestorationCapabilities, err error) {
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
	scope, err := resolveIdentitySession(ctx, session, config, root, identity, ResolveIdentityOptions{Partition: *root.ConfigurationNamingContext, Properties: []string{"msDS-EnabledFeature"}})
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
		feature, readErr := resolveIdentitySession(ctx, session, config, root, featureIdentity, ResolveIdentityOptions{Partition: *root.ConfigurationNamingContext, Properties: []string{"msDS-OptionalFeatureGUID"}})
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

func decodeDeletedObject(object Object, enabled *bool, excludesRecycled bool) DeletedObject {
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

// DeletedObjects performs a scoped, paged search with critical visibility
// controls. Search.ResultLimit and partial results have ordinary Search
// semantics. Extra properties and deactivated links remain copied raw values;
// range responses are incomplete, never silently counted as full attributes.
func (c *Client) DeletedObjects(ctx context.Context, query DeletedObjectQuery) (result DeletedObjectsResult, err error) {
	if err = query.Search.Validate(); err != nil {
		return result, err
	}
	for _, property := range query.Search.Properties {
		if property == "1.1" {
			return result, ErrInvalidProperty
		}
	}
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	result.Source = c.config.Endpoint
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	err = c.read(bounded, func(ctx context.Context) error {
		root, err := restorationRoot(ctx, c.session, c.config.Endpoint)
		if err != nil {
			return err
		}
		controls, err := restorationControls(root, query.IncludeRecycled, query.IncludeDeactivatedLinks)
		if err != nil {
			return err
		}
		options := query.Search
		var identity Identity
		if options.Base != "" {
			identity, err = IdentityByDN(options.Base)
			if err != nil {
				return err
			}
		}
		index, _, err := identityPartition(identity, c.config.Partition, root)
		if err != nil {
			return err
		}
		result.Partition = root.NamingContexts[index]
		if options.Base == "" {
			options.Base = result.Partition
		}
		options.Properties = restorationProperties(options.Properties)
		if options.Filter == "" {
			options.Filter = "(isDeleted=TRUE)"
		} else {
			options.Filter = "(&(isDeleted=TRUE)" + options.Filter + ")"
		}
		var featureErr error
		result.Capabilities, featureErr = restorationFeatureState(ctx, c.session, c.config, root)
		result.Observation, err = searchIdentitySession(ctx, controlledSearchSession{directorySession: c.session, controls: controls}, options)
		for _, object := range result.Observation.Objects {
			decoded := decodeDeletedObject(object, result.Capabilities.RecycleBinEnabled, !query.IncludeRecycled)
			result.Objects = append(result.Objects, decoded)
			err = errors.Join(err, decoded.Error)
		}
		err = errors.Join(err, featureErr)
		result.Complete = result.Observation.Complete && err == nil
		return err
	})
	result.Complete = result.Complete && err == nil
	return result, err
}

func (c *Client) RestoreObject(ctx context.Context, request RestoreObjectRequest) (result ObjectRestorationResult, err error) {
	result.Mode = request.Mode
	if request.Mode > RestoreLegacyTombstone || (request.Mode == RestoreWithRecycleBin && len(request.Attributes) != 0) {
		return result, ErrInvalidObjectRestore
	}
	extra, err := restoreAttributeModifications(request.Attributes)
	if err != nil {
		return result, err
	}
	if err = validateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	if request.NewName != nil && (*request.NewName == "" || !validDirectoryText(*request.NewName)) {
		return result, ErrInvalidObjectRestore
	}
	if request.TargetParent.Form() != 0 {
		if err = validateIdentityOperation(request.TargetParent, ResolveIdentityOptions{Partition: request.Options.Partition}); err != nil {
			return result, err
		}
	}
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	result.Mutation.Source = c.config.Endpoint
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	err = c.read(bounded, func(ctx context.Context) error {
		session, ok := c.session.(ldapWriteSession)
		if !ok {
			return ErrUnsupported
		}
		root, err := restorationRoot(ctx, c.session, c.config.Endpoint)
		if err != nil {
			return err
		}
		controls, err := restorationControls(root, false, false)
		if err != nil {
			return err
		}
		result.Capabilities, err = restorationFeatureState(ctx, c.session, c.config, root)
		if request.Mode == RestoreWithRecycleBin && (err != nil || result.Capabilities.RecycleBinEnabled == nil || !*result.Capabilities.RecycleBinEnabled) {
			return errors.Join(ErrObjectRestoreFeature, err)
		}
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		// Resolve through show-deleted first: the server excludes recycled
		// objects even when their isRecycled attribute is hidden by ACLs.
		deletedSession := controlledSearchSession{directorySession: c.session, controls: controls}
		properties := restorationProperties(objectWriteProperties(request.Options, extra))
		resolved, err := resolveIdentitySession(ctx, deletedSession, c.config, root, request.Identity, ResolveIdentityOptions{Partition: request.Options.Partition, Properties: properties})
		result.Mutation.Partition = resolved.Partition
		result.Mutation.PreflightCandidates = resolved.Candidates
		if errors.Is(err, ErrDirectoryObjectNotFound) {
			// A second, read-only observation distinguishes a visible recycled
			// object from an unobservable/expired identity. Never retry a write.
			if recycledControls, controlErr := restorationControls(root, true, false); controlErr == nil {
				recycled, readErr := resolveIdentitySession(ctx, controlledSearchSession{directorySession: c.session, controls: recycledControls}, c.config, root, request.Identity, ResolveIdentityOptions{Partition: resolved.Partition, Properties: restorationProperties(nil)})
				result.Mutation.PreflightCandidates = append(result.Mutation.PreflightCandidates, recycled.Candidates...)
				if readErr == nil {
					decoded := decodeDeletedObject(*recycled.Object, result.Capabilities.RecycleBinEnabled, false)
					result.Deleted = &decoded
					return errors.Join(ErrObjectNotRestorable, decoded.Error)
				}
				return errors.Join(ErrDeletedObjectUnavailable, err, readErr)
			}
			return errors.Join(ErrDeletedObjectUnavailable, err)
		}
		if err != nil {
			return err
		}
		result.Mutation.Before = resolved.Object
		decoded := decodeDeletedObject(*resolved.Object, result.Capabilities.RecycleBinEnabled, true)
		result.Deleted = &decoded
		if decoded.Error != nil || decoded.GUID == nil || decoded.State == DeletedStateProtected || (decoded.IsRecycled != nil && *decoded.IsRecycled && decoded.State != DeletedStateTombstone) || (request.Mode == RestoreWithRecycleBin && decoded.State != DeletedStateDeleted) {
			return errors.Join(ErrObjectNotRestorable, decoded.Error)
		}
		if err := validateRestorationObject(*resolved.Object, resolved.Partition, root); err != nil {
			return err
		}
		result.Mutation.TargetGUID = decoded.GUID
		if request.Identity.Form() == IdentityFormGUID && request.Identity.String() != decoded.GUID.String() {
			return ErrInvalidResult
		}
		parent := request.TargetParent
		if parent.Form() == 0 {
			if decoded.LastKnownParent == nil {
				return ErrAttributeUnavailable
			}
			parent, err = IdentityByDN(*decoded.LastKnownParent)
			if err != nil {
				return err
			}
		}
		result.Parent, err = resolveIdentitySession(ctx, session, c.config, root, parent, ResolveIdentityOptions{Partition: resolved.Partition, Properties: []string{"objectGUID", "objectClass"}})
		if err != nil {
			return err
		}
		name := request.NewName
		if name == nil {
			name = decoded.LastKnownRDN
		}
		if name == nil || *name == "" || !validDirectoryText(*name) {
			return errors.Join(ErrInvalidObjectRestore, ErrAttributeUnavailable)
		}
		dn, err := parseIdentityDN(resolved.Object.DistinguishedName)
		if err != nil || len(dn[0]) != 1 || dn[0][0].binary {
			return ErrInvalidObjectRestore
		}
		for _, mod := range extra {
			if strings.EqualFold(mod.attribute, dn[0][0].attribute) {
				return fmt.Errorf("%w: naming attribute is supplied by NewName", ErrInvalidObjectRestore)
			}
		}
		result.Mutation.TargetDN = dn[0][0].attribute + "=" + escapeObjectName(*name) + "," + result.Parent.Object.DistinguishedName
		conditional, err := objectWriteControls(root, c.config.Endpoint, request.Options, *decoded.GUID, false)
		if err != nil {
			return err
		}
		controls = append(controls, conditional...)
		mods := []ldapAttributeModification{{operation: 1, attribute: "isDeleted"}, {operation: 2, attribute: "distinguishedName", values: [][]byte{[]byte(result.Mutation.TargetDN)}}}
		mods = append(mods, extra...)
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*decoded.GUID), modifications: mods, controls: controls}, false, &result.Mutation); err != nil {
			return err
		}
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*decoded.GUID), &result.Mutation, properties, false); err != nil {
			return err
		}
		// An ordinary live-object search plus identical GUID and destination
		// verifies restoration, without treating omitted isDeleted as proof.
		actual, err := parseIdentityDN(result.Mutation.After.DistinguishedName)
		wanted, _ := parseIdentityDN(result.Mutation.TargetDN)
		if err != nil || !sameIdentityDN(actual, wanted) {
			return ErrObjectVerification
		}
		for _, attribute := range []string{"isDeleted", "isRecycled"} {
			if values := result.Mutation.After.Values(attribute); values.State == AttributePresent {
				value, err := values.Single()
				if err != nil {
					return errors.Join(ErrObjectVerification, err)
				}
				deleted, err := value.Bool()
				if err != nil || deleted {
					return errors.Join(ErrObjectVerification, err)
				}
			}
		}
		return verifyObjectWrite(&result.Mutation, extra, "")
	})
	return result, classifyObjectWriteError(err)
}

func restoreAttributeModifications(attributes map[string][]RawValue) ([]ldapAttributeModification, error) {
	mods, err := createObjectAttributes(attributes)
	if err != nil {
		return nil, errors.Join(ErrInvalidObjectRestore, err)
	}
	for i := range mods {
		switch strings.ToLower(mods[i].attribute) {
		case "isdeleted", "isrecycled", "lastknownparent", "msds-lastknownrdn", "instancetype", "systemflags":
			return nil, fmt.Errorf("%w: reserved restoration attribute %s", ErrInvalidObjectRestore, mods[i].attribute)
		}
		mods[i].operation = 2
	}
	return mods, nil
}

func validateRestorationObject(object Object, partition string, root RootDSE) error {
	dn, err := parseIdentityDN(object.DistinguishedName)
	if err != nil {
		return err
	}
	nc, err := parseIdentityDN(partition)
	if err != nil {
		return err
	}
	if sameIdentityDN(dn, nc) {
		return ErrObjectNotRestorable
	}
	if root.SchemaNamingContext != nil {
		schema, err := parseIdentityDN(*root.SchemaNamingContext)
		if err != nil {
			return err
		}
		if sameIdentityDN(nc, schema) {
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

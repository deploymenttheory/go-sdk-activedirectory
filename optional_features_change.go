package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// OptionalFeatureChangeRequest identifies the exact feature and scope object.
// Forest/configuration-set scope uses CN=Partitions,<configuration NC>; domain
// scope uses this AD DS server's default domain NC; server scope uses its DSA.
// The connection must already target the naming master for forest scope.
type OptionalFeatureChangeRequest struct {
	FeatureGUID             string
	Scope                   OptionalFeatureScope
	ScopeDN                 string
	AcknowledgeIrreversible bool
}

func (r OptionalFeatureChangeRequest) Validate() error {
	if _, err := optionalFeatureGUIDBytes(r.FeatureGUID); err != nil {
		return err
	}
	if optionalFeatureScopeFlag(r.Scope) == 0 || r.ScopeDN == "" || !validDirectoryText(r.ScopeDN) {
		return ErrInvalidOptionalFeature
	}
	return nil
}

type OptionalFeatureWriteState uint8

const (
	OptionalFeatureWriteNotAttempted OptionalFeatureWriteState = iota
	OptionalFeatureWriteAccepted
	OptionalFeatureWriteRejected
	OptionalFeatureWriteUncertain
)

// OptionalFeatureChangeResult retains an acknowledged write even if subsequent
// readback fails. Verified describes this server's local scope link, not forest
// convergence. Nil enabled values mean unobserved/hidden, not false.
type OptionalFeatureChangeResult struct {
	Feature       OptionalFeature
	Scope         OptionalFeatureScope
	ScopeDN       string
	TargetDSA     string
	Enable        bool
	BeforeEnabled *bool
	AfterEnabled  *bool
	WriteState    OptionalFeatureWriteState
	WriteError    error
	Verified      bool
}

// EnableOptionalFeature uses one documented rootDSE ADD on the pinned endpoint.
// Preflight and readback share the client gate. No role transfer, reconnect,
// referral, automatic retry or rollback occurs. Known irreversible features,
// and any feature without the disablable flag, require explicit acknowledgement.
func (c *Client) EnableOptionalFeature(ctx context.Context, request OptionalFeatureChangeRequest) (OptionalFeatureChangeResult, error) {
	return c.changeOptionalFeature(ctx, request, true)
}

// DisableOptionalFeature rejects irreversible features before native submission.
// A missing response is uncertain; callers must reconcile before another write.
func (c *Client) DisableOptionalFeature(ctx context.Context, request OptionalFeatureChangeRequest) (OptionalFeatureChangeResult, error) {
	return c.changeOptionalFeature(ctx, request, false)
}

func (c *Client) changeOptionalFeature(ctx context.Context, request OptionalFeatureChangeRequest, enable bool) (OptionalFeatureChangeResult, error) {
	result := OptionalFeatureChangeResult{Scope: request.Scope, ScopeDN: request.ScopeDN, Enable: enable}
	if err := request.Validate(); err != nil {
		return result, err
	}
	err := c.read(ctx, func(bounded context.Context) error {
		session, ok := c.session.(ldapModifySession)
		if !ok {
			return ErrUnsupported
		}
		if err := prepareOptionalFeatureChange(bounded, session, request, enable, &result); err != nil {
			return err
		}
		if err := context.Cause(bounded); err != nil {
			return err
		}
		attribute := "disableOptionalFeature"
		if enable {
			attribute = "enableOptionalFeature"
		}
		attempt := session.ldapModify(bounded, "", []ldapModification{{operation: 0, attribute: attribute, value: []byte(result.ScopeDN + ":" + *result.Feature.FeatureGUID)}})
		result.WriteState = OptionalFeatureWriteState(attempt.State)
		result.WriteError = attempt.Err
		if attempt.State == ldapWriteUncertain {
			result.WriteError = errors.Join(ErrOptionalFeatureUncertain, attempt.Err)
			return result.WriteError
		}
		if attempt.State != ldapWriteAccepted {
			if attempt.Err == nil {
				return ErrInvalidResult
			}
			return attempt.Err
		}
		// Accepted remains accepted even if cleanup/cancellation prevents readback.
		if attempt.Err != nil {
			return attempt.Err
		}
		attrs, err := session.baseObject(bounded, result.ScopeDN, []string{"distinguishedName", "objectClass", "msDS-EnabledFeature"})
		if err != nil {
			return errors.Join(ErrOptionalFeatureReadback, err)
		}
		if dn, err := operationMasterObject(attrs, optionalFeatureScopeClass(request.Scope)); err != nil || !strings.EqualFold(dn, result.ScopeDN) {
			return errors.Join(ErrOptionalFeatureReadback, err)
		}
		result.AfterEnabled, err = optionalFeatureEnabled(attrs, result.Feature.DistinguishedName)
		result.Verified = err == nil && result.AfterEnabled != nil && *result.AfterEnabled == enable
		if !result.Verified {
			return errors.Join(ErrOptionalFeatureReadback, err)
		}
		return nil
	})
	var native *LDAPError
	if errors.As(err, &native) && native.Code == 50 {
		err = errors.Join(ErrOptionalFeaturePermission, err)
	}
	return result, err
}

func prepareOptionalFeatureChange(ctx context.Context, session directorySession, request OptionalFeatureChangeRequest, enable bool, result *OptionalFeatureChangeResult) error {
	root, err := optionalFeatureRoot(ctx, session)
	if err != nil {
		return err
	}
	if root.IsSynchronized == nil || !*root.IsSynchronized || root.DSServiceName == nil || *root.DSServiceName == "" || root.Capabilities().Has("1.2.840.113556.1.4.1920") {
		return ErrOptionalFeaturePrerequisite
	}
	// AD LDS can return a GUID bind reference here. Resolve it before comparing
	// the scope/role owner's canonical DN; the reference itself is not a DN.
	dsa, err := session.baseObject(ctx, *root.DSServiceName, []string{"distinguishedName", "objectClass", "msDS-isRODC"})
	if err != nil {
		return err
	}
	result.TargetDSA, err = operationMasterObject(dsa, "nTDSDSA")
	if err != nil {
		return errors.Join(ErrOptionalFeaturePrerequisite, err)
	}
	if root.Capabilities().Type == DirectoryADDS {
		if !strings.EqualFold(result.TargetDSA, *root.DSServiceName) {
			return ErrInvalidResult
		}
		d := rootDSEDecoder{attributes: dsa}
		readOnly := decodeScalar(&d, "msDS-isRODC", parseLDAPBool)
		if readOnly == nil || *readOnly || len(d.errors) > 0 {
			return errors.Join(ErrOptionalFeaturePrerequisite, errors.Join(d.errors...))
		}
	}
	var expected string
	switch request.Scope {
	case OptionalFeatureForest:
		expected = "CN=Partitions," + *root.ConfigurationNamingContext
	case OptionalFeatureDomain:
		if root.Capabilities().Type != DirectoryADDS || root.DefaultNamingContext == nil {
			return ErrOptionalFeatureScope
		}
		expected = *root.DefaultNamingContext
	case OptionalFeatureServer:
		expected = result.TargetDSA
	}
	if !strings.EqualFold(request.ScopeDN, expected) {
		return ErrOptionalFeatureScope
	}
	attrs, err := session.baseObject(ctx, expected, []string{"distinguishedName", "objectClass", "fSMORoleOwner", "msDS-EnabledFeature"})
	if err != nil {
		return err
	}
	dn, err := operationMasterObject(attrs, optionalFeatureScopeClass(request.Scope))
	if err != nil {
		return err
	}
	if !strings.EqualFold(dn, expected) {
		return ErrInvalidResult
	}
	result.ScopeDN = dn
	if request.Scope == OptionalFeatureForest {
		owner, err := operationMasterText(attrs, "fSMORoleOwner")
		if err != nil {
			return err
		}
		if !strings.EqualFold(owner, result.TargetDSA) {
			return ErrOptionalFeatureRole
		}
	}
	search, err := optionalFeatureSearch(ctx, session, root, OptionalFeatureQuery{FeatureGUID: request.FeatureGUID})
	if err != nil {
		return err
	}
	if !search.Complete {
		return ErrIncompleteResult
	}
	if len(search.Objects) == 0 {
		return ErrDirectoryObjectNotFound
	}
	if len(search.Objects) != 1 {
		return ErrInvalidResult
	}
	result.Feature, err = decodeOptionalFeature(search.Objects[0])
	if err != nil {
		return err
	}
	if err := readOptionalFeatureScopes(ctx, session, &result.Feature); err != nil {
		return err
	}
	feature := result.Feature
	if feature.FeatureGUID == nil || !strings.EqualFold(*feature.FeatureGUID, request.FeatureGUID) || feature.Flags == nil || feature.Disablable == nil || feature.DistinguishedName == "" {
		return ErrIncompleteResult
	}
	if *feature.Flags&optionalFeatureScopeFlag(request.Scope) == 0 {
		return ErrOptionalFeatureScope
	}
	knownMinimum := optionalFeatureKnownMinimum(*feature.FeatureGUID)
	if knownMinimum != 0 && request.Scope != OptionalFeatureForest {
		return ErrOptionalFeatureScope
	}
	irreversible := !*feature.Disablable || knownMinimum != 0
	if irreversible && (!enable || !request.AcknowledgeIrreversible) {
		return ErrOptionalFeatureIrreversible
	}
	if enable {
		minimum := knownMinimum
		if feature.RequiredForestLevel != nil && *feature.RequiredForestLevel > minimum {
			minimum = *feature.RequiredForestLevel
		}
		if minimum > 0 && (root.ForestFunctionality == nil || *root.ForestFunctionality < minimum) {
			return ErrOptionalFeaturePrerequisite
		}
		if request.Scope == OptionalFeatureDomain && feature.RequiredDomainLevel != nil && (root.DomainFunctionality == nil || *root.DomainFunctionality < *feature.RequiredDomainLevel) {
			return ErrOptionalFeaturePrerequisite
		}
		if strings.EqualFold(*feature.FeatureGUID, OptionalFeatureDatabase32KPagesGUID) {
			if err := optionalFeature32KPrerequisite(ctx, session, root, result.TargetDSA); err != nil {
				return err
			}
		}
	}
	result.BeforeEnabled, err = optionalFeatureEnabled(attrs, feature.DistinguishedName)
	return err
}

func optionalFeatureScopeClass(scope OptionalFeatureScope) string {
	switch scope {
	case OptionalFeatureForest:
		return "crossRefContainer"
	case OptionalFeatureDomain:
		return "domainDNS"
	case OptionalFeatureServer:
		return "nTDSDSA"
	}
	return ""
}

func optionalFeatureKnownMinimum(guid string) uint32 {
	switch strings.ToLower(guid) {
	case OptionalFeatureRecycleBinGUID:
		return 4
	case OptionalFeaturePAMGUID:
		return 7
	case OptionalFeatureDatabase32KPagesGUID:
		return 10
	}
	return 0
}

func optionalFeatureEnabled(attrs map[string][][]byte, featureDN string) (*bool, error) {
	for name := range attrs {
		if strings.HasPrefix(strings.ToLower(name), "msds-enabledfeature;range=") {
			return nil, ErrIncompleteResult
		}
	}
	if _, ok := attrs["msds-enabledfeature"]; !ok {
		return nil, nil
	}
	d := rootDSEDecoder{attributes: attrs}
	values := d.texts("msDS-EnabledFeature")
	if len(d.errors) > 0 {
		return nil, errors.Join(d.errors...)
	}
	enabled := false
	for _, value := range values {
		if strings.EqualFold(value, featureDN) {
			enabled = true
		}
	}
	return &enabled, nil
}

func optionalFeature32KPrerequisite(ctx context.Context, session directorySession, root RootDSE, target string) error {
	options, err := (SearchOptions{Base: *root.ConfigurationNamingContext, Scope: ScopeSubtree, Filter: "(objectClass=nTDSDSA)", Properties: []string{"distinguishedName", "objectClass", "msDS-JetDBPageSize"}}).normalized()
	if err != nil {
		return err
	}
	cursor, err := session.startSearch(ctx, options)
	if err != nil {
		return err
	}
	result, err := collectSearch(ctx, cursor, options)
	if err != nil {
		return err
	}
	if !result.Complete || len(result.Objects) == 0 {
		return ErrOptionalFeaturePrerequisite
	}
	found := false
	for _, object := range result.Objects {
		d := rootDSEDecoder{attributes: object.Attributes}
		size := decodeScalar(&d, "msDS-JetDBPageSize", parseUint32)
		if size == nil || *size != 32768 || len(d.errors) > 0 {
			return errors.Join(ErrOptionalFeaturePrerequisite, errors.Join(d.errors...))
		}
		if strings.EqualFold(object.DistinguishedName, target) {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("%w: current DSA absent from 32K capability enumeration", ErrOptionalFeaturePrerequisite)
	}
	return nil
}

package model

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
	if _, err := InternalOptionalFeatureGUIDBytes(r.FeatureGUID); err != nil {
		return err
	}
	if InternalOptionalFeatureScopeFlag(r.Scope) == 0 || r.ScopeDN == "" ||
		!InternalValidDirectoryText(r.ScopeDN) {
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

func InternalPrepareOptionalFeatureChange(
	ctx context.Context,
	session InternalDirectorySession,
	request OptionalFeatureChangeRequest,
	enable bool,
	result *OptionalFeatureChangeResult,
) error {
	root, err := InternalOptionalFeatureRoot(ctx, session)
	if err != nil {
		return err
	}
	if root.IsSynchronized == nil || !*root.IsSynchronized || root.DSServiceName == nil ||
		*root.DSServiceName == "" ||
		root.Capabilities().Has("1.2.840.113556.1.4.1920") {
		return ErrOptionalFeaturePrerequisite
	}
	// AD LDS can return a GUID bind reference here. Resolve it before comparing
	// the scope/role owner's canonical DN; the reference itself is not a DN.
	dsa, err := session.InternalBaseObject(
		ctx,
		*root.DSServiceName,
		[]string{"distinguishedName", "objectClass", "msDS-isRODC"},
	)
	if err != nil {
		return err
	}
	result.TargetDSA, err = InternalOperationMasterObject(dsa, "nTDSDSA")
	if err != nil {
		return errors.Join(ErrOptionalFeaturePrerequisite, err)
	}
	if root.Capabilities().Type == DirectoryADDS {
		if !strings.EqualFold(result.TargetDSA, *root.DSServiceName) {
			return ErrInvalidResult
		}
		d := InternalRootDSEDecoder{InternalAttributes: dsa}
		readOnly := InternalDecodeScalar(&d, "msDS-isRODC", InternalParseLDAPBool)
		if readOnly == nil || *readOnly || len(d.InternalErrors) > 0 {
			return errors.Join(ErrOptionalFeaturePrerequisite, errors.Join(d.InternalErrors...))
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
	attrs, err := session.InternalBaseObject(
		ctx,
		expected,
		[]string{"distinguishedName", "objectClass", "fSMORoleOwner", "msDS-EnabledFeature"},
	)
	if err != nil {
		return err
	}
	dn, err := InternalOperationMasterObject(
		attrs,
		InternalOptionalFeatureScopeClass(request.Scope),
	)
	if err != nil {
		return err
	}
	if !strings.EqualFold(dn, expected) {
		return ErrInvalidResult
	}
	result.ScopeDN = dn
	if request.Scope == OptionalFeatureForest {
		owner, err := InternalOperationMasterText(attrs, "fSMORoleOwner")
		if err != nil {
			return err
		}
		if !strings.EqualFold(owner, result.TargetDSA) {
			return ErrOptionalFeatureRole
		}
	}
	search, err := InternalOptionalFeatureSearch(
		ctx,
		session,
		root,
		OptionalFeatureQuery{FeatureGUID: request.FeatureGUID},
	)
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
	result.Feature, err = InternalDecodeOptionalFeature(search.Objects[0])
	if err != nil {
		return err
	}
	if err := InternalReadOptionalFeatureScopes(ctx, session, &result.Feature); err != nil {
		return err
	}
	feature := result.Feature
	if feature.FeatureGUID == nil ||
		!strings.EqualFold(*feature.FeatureGUID, request.FeatureGUID) ||
		feature.Flags == nil ||
		feature.Disablable == nil ||
		feature.DistinguishedName == "" {
		return ErrIncompleteResult
	}
	if *feature.Flags&InternalOptionalFeatureScopeFlag(request.Scope) == 0 {
		return ErrOptionalFeatureScope
	}
	knownMinimum := InternalOptionalFeatureKnownMinimum(*feature.FeatureGUID)
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
		if request.Scope == OptionalFeatureDomain && feature.RequiredDomainLevel != nil &&
			(root.DomainFunctionality == nil || *root.DomainFunctionality < *feature.RequiredDomainLevel) {
			return ErrOptionalFeaturePrerequisite
		}
		if strings.EqualFold(*feature.FeatureGUID, OptionalFeatureDatabase32KPagesGUID) {
			if err := InternalOptionalFeature32KPrerequisite(
				ctx,
				session,
				root,
				result.TargetDSA,
			); err != nil {
				return err
			}
		}
	}
	result.BeforeEnabled, err = InternalOptionalFeatureEnabled(attrs, feature.DistinguishedName)
	return err
}

func InternalOptionalFeatureScopeClass(scope OptionalFeatureScope) string {
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

func InternalOptionalFeatureKnownMinimum(guid string) uint32 {
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

func InternalOptionalFeatureEnabled(attrs map[string][][]byte, featureDN string) (*bool, error) {
	for name := range attrs {
		if strings.HasPrefix(strings.ToLower(name), "msds-enabledfeature;range=") {
			return nil, ErrIncompleteResult
		}
	}
	if _, ok := attrs["msds-enabledfeature"]; !ok {
		return nil, nil
	}
	d := InternalRootDSEDecoder{InternalAttributes: attrs}
	values := d.InternalTexts("msDS-EnabledFeature")
	if len(d.InternalErrors) > 0 {
		return nil, errors.Join(d.InternalErrors...)
	}
	enabled := false
	for _, value := range values {
		if strings.EqualFold(value, featureDN) {
			enabled = true
		}
	}
	return &enabled, nil
}

func InternalOptionalFeature32KPrerequisite(
	ctx context.Context,
	session InternalDirectorySession,
	root RootDSE,
	target string,
) error {
	options, err := InternalSearchOptionsNormalized(
		(SearchOptions{
			Base:       *root.ConfigurationNamingContext,
			Scope:      ScopeSubtree,
			Filter:     "(objectClass=nTDSDSA)",
			Properties: []string{"distinguishedName", "objectClass", "msDS-JetDBPageSize"},
		}),
	)
	if err != nil {
		return err
	}
	cursor, err := session.InternalStartSearch(ctx, options)
	if err != nil {
		return err
	}
	result, err := InternalCollectSearch(ctx, cursor, options)
	if err != nil {
		return err
	}
	if !result.Complete || len(result.Objects) == 0 {
		return ErrOptionalFeaturePrerequisite
	}
	found := false
	for _, object := range result.Objects {
		d := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
		size := InternalDecodeScalar(&d, "msDS-JetDBPageSize", InternalParseUint32)
		if size == nil || *size != 32768 || len(d.InternalErrors) > 0 {
			return errors.Join(ErrOptionalFeaturePrerequisite, errors.Join(d.InternalErrors...))
		}
		if strings.EqualFold(object.DistinguishedName, target) {
			found = true
		}
	}
	if !found {
		return fmt.Errorf(
			"%w: current DSA absent from 32K capability enumeration",
			ErrOptionalFeaturePrerequisite,
		)
	}
	return nil
}

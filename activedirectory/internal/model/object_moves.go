package model

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
)

const InternalObjectCrossDomainMoveControl = "1.2.840.113556.1.4.521"

var (
	ErrInvalidObjectMove   = errors.New("invalid directory object move")
	ErrObjectMoveForbidden = errors.New("observed object or destination does not permit this move")
	ErrMoveRIDMaster       = errors.New(
		"cross-domain move endpoint is not its domain's observed RID master",
	)
	ErrMoveForest = errors.New(
		"cross-domain move requires two domains in the same observed forest",
	)
	ErrMoveDelegation = errors.New(
		"cross-domain move requires explicitly enabled and verified delegated Kerberos authentication",
	)
)

// MoveSecurity describes the actual source LDAP Kerberos context. Complete means
// the delegated Kerberos and mutual-authentication checks succeeded. It never
// contains credentials, security handles, tickets or secret key material.
type MoveSecurity struct {
	Package      string
	ContextFlags uint32
	Delegated    bool
	Complete     bool
	// Protection contains measured portable session facts. ContextFlags above
	// remain SSPI-specific and are not populated with GSS flag values.
	Protection SessionProtection
}

// ObjectMoveResult keeps Mutation.Source/Partition on the write endpoint.
// Mutation.After and its uSNChanged are observed on Destination in
// DestinationPartition; cross-domain USNs cannot become source preconditions.
type ObjectMoveResult struct {
	Mutation               ObjectMutationResult
	Destination            Endpoint
	DestinationPartition   string
	CrossDomain            bool
	Parent                 IdentityResult
	SourceObservation      DirectoryObservation
	DestinationObservation DirectoryObservation
	Security               MoveSecurity
}

type InternalMoveSecuritySession interface {
	InternalMoveSecurity(context.Context) (MoveSecurity, error)
}

func InternalSameMoveDN(a, b string) bool {
	x, xerr := InternalParseIdentityDN(a)
	y, yerr := InternalParseIdentityDN(b)
	return xerr == nil && yerr == nil && InternalSameIdentityDN(x, y)
}

func InternalMoveObjectGUID(object Object) (GUID, error) {
	value, err := object.Values("objectGUID").Single()
	if err != nil {
		return GUID{}, err
	}
	return value.GUID()
}

func InternalMoveText(object Object, attribute string) (string, error) {
	value, err := object.Values(attribute).Single()
	if err != nil {
		return "", err
	}
	return value.Text()
}

func InternalMoveFlags(object Object, attribute string, required bool) (uint32, error) {
	values := object.Values(attribute)
	if values.State == AttributeAbsent && !required {
		return 0, nil
	}
	value, err := values.Single()
	if err != nil {
		return 0, err
	}
	flags, err := value.Flags32()
	return uint32(flags), err
}

func InternalMoveClasses(object Object) ([]string, error) {
	values := object.Values("objectClass")
	if values.State != AttributePresent || len(values.Values) == 0 {
		return nil, ErrAttributeUnavailable
	}
	var classes []string
	for _, value := range values.Values {
		class, err := value.Text()
		if err != nil {
			return nil, err
		}
		classes = append(classes, strings.ToLower(class))
	}
	return classes, nil
}

func InternalMoveRequireClass(object Object, class string) error {
	classes, err := InternalMoveClasses(object)
	if err != nil {
		return err
	}
	if !slices.Contains(classes, strings.ToLower(class)) {
		return ErrInvalidResult
	}
	return nil
}

func InternalMoveLiveParent(object Object) error {
	for _, attribute := range []string{"isDeleted", "isRecycled"} {
		values := object.Values(attribute)
		if values.State == AttributeAbsent {
			continue
		}
		value, err := values.Single()
		if err != nil {
			return err
		}
		flag, err := value.Bool()
		if err != nil {
			return err
		}
		if flag {
			return ErrObjectMoveForbidden
		}
	}
	return nil
}

func InternalValidateMoveParent(object Object, identity Identity) error {
	if err := InternalMoveLiveParent(object); err != nil {
		return err
	}
	if _, err := InternalMoveClasses(object); err != nil {
		return err
	}
	guid, err := InternalMoveObjectGUID(object)
	if err != nil {
		return err
	}
	if identity.Form() == IdentityFormGUID && identity.String() != guid.String() {
		return ErrInvalidResult
	}
	return nil
}

func InternalValidateMoveObject(
	object, parent Object,
	root RootDSE,
	partition string,
	cross bool,
) error {
	if err := InternalMoveLiveParent(object); err != nil {
		return err
	}
	classes, err := InternalMoveClasses(object)
	if err != nil {
		return err
	}
	dn, err := InternalParseIdentityDN(object.DistinguishedName)
	if err != nil {
		return err
	}
	np, err := InternalParseIdentityDN(parent.DistinguishedName)
	if err != nil {
		return err
	}
	if InternalSameMoveDN(object.DistinguishedName, partition) || InternalIdentityWithin(np, dn) {
		return ErrObjectMoveForbidden
	}
	if root.SchemaNamingContext != nil && InternalSameMoveDN(partition, *root.SchemaNamingContext) {
		return ErrObjectMoveForbidden
	}
	instance, err := InternalMoveFlags(object, "instanceType", cross)
	if err != nil {
		return err
	}
	if instance&1 != 0 || (cross && instance&4 == 0) {
		return ErrObjectMoveForbidden
	}
	flags, err := InternalMoveFlags(object, "systemFlags", false)
	if err != nil {
		return err
	}
	if root.Capabilities().Type == DirectoryADDS && root.DefaultNamingContext != nil &&
		InternalSameMoveDN(partition, *root.DefaultNamingContext) &&
		flags&0x04000000 != 0 {
		return ErrObjectMoveForbidden
	}
	if root.ConfigurationNamingContext != nil &&
		InternalSameMoveDN(partition, *root.ConfigurationNamingContext) &&
		flags&0x20000000 == 0 {
		if flags&0x10000000 == 0 || len(dn) < 4 || len(np) < 3 ||
			!InternalSameIdentityDN(dn[3:], np[2:]) {
			return ErrObjectMoveForbidden
		}
	}
	if err := internalValidateMoveClasses(classes, root.Capabilities().Type, cross); err != nil {
		return err
	}
	if !cross {
		return nil
	}
	return internalValidateCrossDomainMoveAccount(object, flags)
}

func internalValidateMoveClasses(classes []string, kind DirectoryType, cross bool) error {
	for _, class := range classes {
		if class == "classschema" || class == "attributeschema" {
			return ErrObjectMoveForbidden
		}
		if kind == DirectoryADDS &&
			(class == "secret" || class == "trusteddomain") {
			return ErrObjectMoveForbidden
		}
		if cross &&
			slices.Contains(
				strings.Fields(
					"addressbookcontainer attributeschema builtindomain certificationauthority classschema configuration "+
						"crldistributionpoint crossref crossrefcontainer dmd domain dsa foreignsecurityprincipal infrastructureupdate "+
						"linktrackobjectmovetable linktrackomtentry linktrackvolentry linktrackvolumetable lostandfound "+
						"ntdsconnection ntdsdsa ntdssitesettings ridmanager ridset samdomain samdomainbase samserver site "+
						"sitelink sitelinkbridge sitescontainer subnet subnetcontainer trusteddomain",
				),
				class,
			) {
			return fmt.Errorf("%w: forbidden cross-domain class %s", ErrObjectMoveForbidden, class)
		}
	}
	return nil
}

func internalValidateCrossDomainMoveAccount(object Object, flags uint32) error {
	if flags&(0x80000000|0x04000000) != 0 {
		return ErrObjectMoveForbidden
	}
	if values := object.Values("isCriticalSystemObject"); values.State != AttributeAbsent {
		value, err := values.Single()
		if err != nil {
			return err
		}
		critical, err := value.Bool()
		if err != nil {
			return err
		}
		if critical {
			return ErrObjectMoveForbidden
		}
	}
	account, err := InternalMoveFlags(object, "userAccountControl", false)
	if err != nil {
		return err
	}
	if account&(0x800|0x2000) != 0 {
		return ErrObjectMoveForbidden
	}
	group, err := InternalMoveFlags(object, "groupType", false)
	if err != nil {
		return err
	}
	if group&1 != 0 {
		return ErrObjectMoveForbidden
	}
	if values := object.Values("objectSid"); values.State != AttributeAbsent {
		value, err := values.Single()
		if err != nil {
			return err
		}
		sid, err := value.SID()
		if err != nil {
			return err
		}
		encoded := sid.Bytes()
		if len(encoded) < 12 || binary.LittleEndian.Uint32(encoded[len(encoded)-4:]) <= 1000 {
			return ErrObjectMoveForbidden
		}
	}
	return nil
}

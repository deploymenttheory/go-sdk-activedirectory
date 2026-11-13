package activedirectory

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

const objectCrossDomainMoveControl = "1.2.840.113556.1.4.521"

var (
	ErrInvalidObjectMove   = errors.New("invalid directory object move")
	ErrObjectMoveForbidden = errors.New("observed object or destination does not permit this move")
	ErrMoveRIDMaster       = errors.New("cross-domain move endpoint is not its domain's observed RID master")
	ErrMoveForest          = errors.New("cross-domain move requires two domains in the same observed forest")
	ErrMoveDelegation      = errors.New("cross-domain move requires explicitly enabled and verified delegated Kerberos authentication")
)

// MoveObjectRequest preserves the RDN and GUID using one native ModifyDN.
// TargetParent accepts DN or GUID. Nil Destination means a same-partition move
// on this Client (AD DS or AD LDS). A distinct authenticated Destination opts
// into a cross-domain AD DS move; its credentials are never forwarded.
type MoveObjectRequest struct {
	Identity     Identity
	TargetParent Identity
	Destination  *Client
	// DestinationPartition scopes a GUID parent on Destination. Empty follows
	// that client's configured/default partition. Unused for local moves.
	DestinationPartition string
	Options              ObjectMutationOptions
}

// MoveSecurity describes the actual source LDAP SSPI context. Complete means
// the delegated Kerberos and mutual-authentication checks succeeded. It never
// contains credentials, security handles, tickets or secret key material.
type MoveSecurity struct {
	Package      string
	ContextFlags uint32
	Delegated    bool
	Complete     bool
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

type moveSecuritySession interface {
	moveSecurity(context.Context) (MoveSecurity, error)
}

// MoveObject never copy/deletes, rebinds, changes passwords, retries or rolls
// back. Cross-domain server rejection may still have partial effects; inspect
// Mutation even on error. Destination readback verifies GUID and location, not
// passwords or every retained attribute. Preflight is not a transaction.
func (c *Client) MoveObject(ctx context.Context, request MoveObjectRequest) (result ObjectMoveResult, err error) {
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	if err := validateObjectOptions(request.TargetParent, ObjectMutationOptions{Partition: request.DestinationPartition}); err != nil {
		return result, err
	}
	if request.Destination == nil && request.DestinationPartition != "" {
		return result, ErrInvalidObjectMove
	}
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	result.Mutation.Source = c.config.Endpoint
	result.Destination = c.config.Endpoint
	result.CrossDomain = request.Destination != nil
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	var destinationRoot RootDSE
	var destinationForest GUID
	if result.CrossDomain {
		destination := request.Destination
		if destination == c {
			return result, ErrInvalidObjectMove
		}
		if destination.session == nil {
			return result, ErrClosed
		}
		result.Destination = destination.config.Endpoint
		if !c.config.AllowDelegation || c.config.Authentication != AuthenticationNegotiate {
			return result, ErrMoveDelegation
		}
		// Never hold two client gates: reciprocal moves cannot deadlock. Every
		// preflight observation can race a server-side change; the server remains
		// authoritative for ownership, access, class and membership constraints.
		err = destination.read(bounded, func(ctx context.Context) error {
			var readErr error
			destinationRoot, readErr = moveRoot(ctx, destination, &result.DestinationObservation, true)
			if readErr != nil {
				return readErr
			}
			result.Parent, readErr = resolveIdentitySession(ctx, destination.session, destination.config, destinationRoot, request.TargetParent, ResolveIdentityOptions{Partition: request.DestinationPartition, Properties: []string{"objectGUID", "objectClass", "isDeleted", "isRecycled", "instanceType"}})
			result.DestinationPartition = result.Parent.Partition
			if readErr != nil {
				return readErr
			}
			if readErr = validateMoveParent(*result.Parent.Object, request.TargetParent); readErr != nil {
				return readErr
			}
			destinationForest, readErr = moveDomainPreflight(ctx, destination, destinationRoot, result.DestinationPartition, &result.DestinationObservation)
			result.DestinationObservation.Complete = readErr == nil
			return readErr
		})
		if err != nil {
			return result, classifyObjectWriteError(err)
		}
	}
	err = c.read(bounded, func(ctx context.Context) error {
		session, ok := c.session.(ldapWriteSession)
		if !ok {
			return ErrUnsupported
		}
		root, err := moveRoot(ctx, c, &result.SourceObservation, result.CrossDomain)
		if err != nil {
			return err
		}
		properties := append(objectWriteProperties(request.Options, nil), "systemFlags", "instanceType", "isDeleted", "isRecycled", "isCriticalSystemObject", "userAccountControl", "objectSid", "groupType")
		resolved, err := resolveIdentitySession(ctx, session, c.config, root, request.Identity, ResolveIdentityOptions{Partition: request.Options.Partition, Properties: properties})
		result.Mutation.Partition = resolved.Partition
		result.Mutation.PreflightCandidates = resolved.Candidates
		if err != nil {
			return err
		}
		result.Mutation.Before = resolved.Object
		guid, err := moveObjectGUID(*resolved.Object)
		if err != nil {
			return err
		}
		result.Mutation.TargetGUID = &guid
		if request.Identity.Form() == IdentityFormGUID && request.Identity.String() != guid.String() {
			return ErrInvalidResult
		}
		if result.CrossDomain {
			if sameMoveDN(resolved.Partition, result.DestinationPartition) {
				return ErrInvalidObjectMove
			}
			forest, err := moveDomainPreflight(ctx, c, root, resolved.Partition, &result.SourceObservation)
			if err != nil {
				return err
			}
			if forest != destinationForest || root.RootDomainNamingContext == nil || destinationRoot.RootDomainNamingContext == nil || !sameMoveDN(*root.RootDomainNamingContext, *destinationRoot.RootDomainNamingContext) {
				return ErrMoveForest
			}
			if !slices.Contains(root.SupportedControls, objectCrossDomainMoveControl) {
				return ErrObjectControlUnsupported
			}
			security, ok := session.(moveSecuritySession)
			if !ok {
				return errors.Join(ErrMoveDelegation, ErrUnsupported)
			}
			result.Security, err = security.moveSecurity(ctx)
			if err != nil {
				return err
			}
			if !result.Security.Complete || !result.Security.Delegated || !strings.EqualFold(result.Security.Package, "Kerberos") {
				return ErrMoveDelegation
			}
		} else {
			result.Parent, err = resolveIdentitySession(ctx, session, c.config, root, request.TargetParent, ResolveIdentityOptions{Partition: resolved.Partition, Properties: []string{"objectGUID", "objectClass", "isDeleted", "isRecycled", "instanceType"}})
			result.DestinationPartition = result.Parent.Partition
			if err != nil {
				return err
			}
			if err := validateMoveParent(*result.Parent.Object, request.TargetParent); err != nil {
				return err
			}
		}
		if err := validateMoveObject(*resolved.Object, *result.Parent.Object, root, resolved.Partition, result.CrossDomain); err != nil {
			return err
		}
		parts, err := splitIdentityDN(resolved.Object.DistinguishedName, ',')
		if err != nil || len(parts) < 2 {
			return ErrInvalidObjectMove
		}
		result.Mutation.TargetDN = parts[0] + "," + result.Parent.Object.DistinguishedName
		controls, err := objectWriteControls(root, c.config.Endpoint, request.Options, guid, false)
		if err != nil {
			return err
		}
		if result.CrossDomain {
			// Raw UTF-8 DNS hostname: no BER inner OCTET STRING and no NUL.
			controls = append(controls, ldapWriteControl{oid: objectCrossDomainMoveControl, critical: true, value: []byte(*destinationRoot.DNSHostName)})
		}
		result.SourceObservation.Complete = true
		writeErr := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteRename, dn: objectGUIDTarget(guid), newRDN: parts[0], newParent: result.Parent.Object.DistinguishedName, deleteOldRDN: true, controls: controls}, false, &result.Mutation)
		result.Mutation.PartialEffectsPossible = result.CrossDomain && result.Mutation.State != ObjectWriteNotAttempted
		if writeErr != nil {
			return writeErr
		}
		if result.CrossDomain {
			return nil
		}
		if err := observeObjectMove(ctx, c, root, properties, &result); err != nil {
			return errors.Join(ErrObjectReadback, err)
		}
		return nil
	})
	if err == nil && result.CrossDomain {
		err = request.Destination.read(bounded, func(ctx context.Context) error {
			return observeObjectMove(ctx, request.Destination, destinationRoot, objectWriteProperties(request.Options, nil), &result)
		})
		if err != nil {
			err = errors.Join(ErrObjectReadback, err)
		}
	}
	return result, classifyObjectWriteError(err)
}

func moveRoot(ctx context.Context, client *Client, observation *DirectoryObservation, cross bool) (RootDSE, error) {
	root, err := readIdentityRoot(ctx, client.session)
	observation.Source, observation.RootDSE = client.config.Endpoint, root
	if err != nil {
		return root, err
	}
	if root.Capabilities().Type == DirectoryUnknown || (cross && root.Capabilities().Type != DirectoryADDS) {
		return root, ErrUnsupportedDirectory
	}
	if root.Capabilities().Type == DirectoryADDS && (client.config.Endpoint.Port == 3268 || client.config.Endpoint.Port == 3269) {
		return root, ErrObjectWriteTarget
	}
	// LDAP_CAP_ACTIVE_DIRECTORY_PARTIAL_SECRETS_OID advertises an RODC.
	if root.Capabilities().Type == DirectoryADDS && root.Capabilities().Has("1.2.840.113556.1.4.1920") {
		return root, ErrObjectWriteTarget
	}
	if cross {
		if root.DNSHostName == nil || !validServerHost(*root.DNSHostName) {
			return root, ErrInvalidResult
		}
		if _, err := netip.ParseAddr(*root.DNSHostName); err == nil {
			return root, ErrInvalidResult
		}
		if !strings.EqualFold(strings.TrimSuffix(*root.DNSHostName, "."), strings.TrimSuffix(client.config.Endpoint.Host, ".")) {
			return root, ErrObjectWriteTarget
		}
	}
	return root, nil
}

// Follow the domain's actual rIDManagerReference (never a guessed CN), as in
// operation-master workflows. fSMORoleOwner must identify this connected DSA.
// The server also checks effective ownership after replication and at dispatch.
func moveDomainPreflight(ctx context.Context, client *Client, root RootDSE, partition string, observation *DirectoryObservation) (GUID, error) {
	if root.DefaultNamingContext == nil || root.ConfigurationNamingContext == nil || root.DSServiceName == nil || !sameMoveDN(partition, *root.DefaultNamingContext) {
		return GUID{}, ErrMoveForest
	}
	read := func(dn, nc string, properties []string) (*Object, error) {
		identity, err := IdentityByDN(dn)
		if err != nil {
			return nil, err
		}
		resolved, err := resolveIdentitySession(ctx, client.session, client.config, root, identity, ResolveIdentityOptions{Partition: nc, Properties: properties})
		observation.Objects = append(observation.Objects, resolved.Candidates...)
		return resolved.Object, err
	}
	domain, err := read(partition, partition, []string{"objectGUID", "objectClass", "instanceType", "rIDManagerReference"})
	if err != nil {
		return GUID{}, err
	}
	if err := moveRequireClass(*domain, "domainDNS"); err != nil {
		return GUID{}, err
	}
	flags, err := moveFlags(*domain, "instanceType", true)
	if err != nil {
		return GUID{}, err
	}
	if flags&5 != 5 {
		return GUID{}, ErrObjectWriteTarget
	}
	managerDN, err := moveText(*domain, "rIDManagerReference")
	if err != nil {
		return GUID{}, err
	}
	manager, err := read(managerDN, partition, []string{"objectClass", "fSMORoleOwner"})
	if err != nil {
		return GUID{}, err
	}
	if err := moveRequireClass(*manager, "rIDManager"); err != nil {
		return GUID{}, err
	}
	owner, err := moveText(*manager, "fSMORoleOwner")
	if err != nil {
		return GUID{}, err
	}
	if !sameMoveDN(owner, *root.DSServiceName) {
		return GUID{}, ErrMoveRIDMaster
	}
	forest, err := read(*root.ConfigurationNamingContext, *root.ConfigurationNamingContext, []string{"objectGUID", "objectClass"})
	if err != nil {
		return GUID{}, err
	}
	if err := moveRequireClass(*forest, "configuration"); err != nil {
		return GUID{}, err
	}
	return moveObjectGUID(*forest)
}

func observeObjectMove(ctx context.Context, client *Client, root RootDSE, properties []string, result *ObjectMoveResult) error {
	// The shared observer scopes to Mutation.Partition. Use a copy so the
	// public mutation continues to describe its source naming context.
	observed := result.Mutation
	observed.Partition = result.DestinationPartition
	err := observeObjectWrite(ctx, client.session, client.config, root, objectGUIDIdentity(*observed.TargetGUID), &observed, append(properties, "isDeleted", "isRecycled"), false)
	result.Mutation.After, result.Mutation.ReadbackCandidates, result.Mutation.ReadbackComplete = observed.After, observed.ReadbackCandidates, observed.ReadbackComplete
	if err != nil {
		return err
	}
	if !sameMoveDN(observed.After.DistinguishedName, result.Mutation.TargetDN) {
		return ErrObjectVerification
	}
	if err := moveLiveParent(*observed.After); err != nil {
		return errors.Join(ErrObjectVerification, err)
	}
	result.Mutation.Verified = true
	return nil
}

func sameMoveDN(a, b string) bool {
	x, xerr := parseIdentityDN(a)
	y, yerr := parseIdentityDN(b)
	return xerr == nil && yerr == nil && sameIdentityDN(x, y)
}
func moveObjectGUID(object Object) (GUID, error) {
	value, err := object.Values("objectGUID").Single()
	if err != nil {
		return GUID{}, err
	}
	return value.GUID()
}
func moveText(object Object, attribute string) (string, error) {
	value, err := object.Values(attribute).Single()
	if err != nil {
		return "", err
	}
	return value.Text()
}
func moveFlags(object Object, attribute string, required bool) (uint32, error) {
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
func moveClasses(object Object) ([]string, error) {
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
func moveRequireClass(object Object, class string) error {
	classes, err := moveClasses(object)
	if err != nil {
		return err
	}
	if !slices.Contains(classes, strings.ToLower(class)) {
		return ErrInvalidResult
	}
	return nil
}
func moveLiveParent(object Object) error {
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

func validateMoveParent(object Object, identity Identity) error {
	if err := moveLiveParent(object); err != nil {
		return err
	}
	if _, err := moveClasses(object); err != nil {
		return err
	}
	guid, err := moveObjectGUID(object)
	if err != nil {
		return err
	}
	if identity.Form() == IdentityFormGUID && identity.String() != guid.String() {
		return ErrInvalidResult
	}
	return nil
}

func validateMoveObject(object, parent Object, root RootDSE, partition string, cross bool) error {
	if err := moveLiveParent(object); err != nil {
		return err
	}
	classes, err := moveClasses(object)
	if err != nil {
		return err
	}
	dn, err := parseIdentityDN(object.DistinguishedName)
	if err != nil {
		return err
	}
	np, err := parseIdentityDN(parent.DistinguishedName)
	if err != nil {
		return err
	}
	if sameMoveDN(object.DistinguishedName, partition) || identityWithin(np, dn) {
		return ErrObjectMoveForbidden
	}
	if root.SchemaNamingContext != nil && sameMoveDN(partition, *root.SchemaNamingContext) {
		return ErrObjectMoveForbidden
	}
	instance, err := moveFlags(object, "instanceType", cross)
	if err != nil {
		return err
	}
	if instance&1 != 0 || (cross && instance&4 == 0) {
		return ErrObjectMoveForbidden
	}
	flags, err := moveFlags(object, "systemFlags", false)
	if err != nil {
		return err
	}
	if root.Capabilities().Type == DirectoryADDS && root.DefaultNamingContext != nil && sameMoveDN(partition, *root.DefaultNamingContext) && flags&0x04000000 != 0 {
		return ErrObjectMoveForbidden
	}
	if root.ConfigurationNamingContext != nil && sameMoveDN(partition, *root.ConfigurationNamingContext) && flags&0x20000000 == 0 {
		if flags&0x10000000 == 0 || len(dn) < 4 || len(np) < 3 || !sameIdentityDN(dn[3:], np[2:]) {
			return ErrObjectMoveForbidden
		}
	}
	for _, class := range classes {
		if class == "classschema" || class == "attributeschema" {
			return ErrObjectMoveForbidden
		}
		if root.Capabilities().Type == DirectoryADDS && (class == "secret" || class == "trusteddomain") {
			return ErrObjectMoveForbidden
		}
		if cross && slices.Contains(strings.Fields("addressbookcontainer attributeschema builtindomain certificationauthority classschema configuration crldistributionpoint crossref crossrefcontainer dmd domain dsa foreignsecurityprincipal infrastructureupdate linktrackobjectmovetable linktrackomtentry linktrackvolentry linktrackvolumetable lostandfound ntdsconnection ntdsdsa ntdssitesettings ridmanager ridset samdomain samdomainbase samserver site sitelink sitelinkbridge sitescontainer subnet subnetcontainer trusteddomain"), class) {
			return fmt.Errorf("%w: forbidden cross-domain class %s", ErrObjectMoveForbidden, class)
		}
	}
	if !cross {
		return nil
	}
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
	account, err := moveFlags(object, "userAccountControl", false)
	if err != nil {
		return err
	}
	if account&(0x800|0x2000) != 0 {
		return ErrObjectMoveForbidden
	}
	group, err := moveFlags(object, "groupType", false)
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

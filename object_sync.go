package activedirectory

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
)

var (
	ErrInvalidObjectSync        = errors.New("invalid single-object synchronization request")
	ErrObjectSyncCapability     = errors.New("server cannot perform the requested object synchronization")
	ErrObjectSyncIdentity       = errors.New("object synchronization identities or naming contexts do not match")
	ErrObjectSyncPermission     = errors.New("object synchronization access denied")
	ErrObjectSyncPasswordPolicy = errors.New("RODC password replication policy does not allow this account")
	ErrObjectSyncUncertain      = errors.New("object synchronization outcome is unknown; reconcile before another write")
	ErrObjectSyncReadback       = errors.New("object synchronization readback did not verify the requested observation")
)

// SyncObjectIdentity selects exactly one object on Source. ObjectGUID contains
// the 16 LDAP objectGUID octets (Windows GUID byte order), not UTF-8 text.
type SyncObjectIdentity struct {
	DistinguishedName string
	ObjectGUID        []byte
}

// SyncObjectRequest requests one object from Source on the destination Client.
// Partition is mandatory and must be the object's containing NC on both DCs.
// Source credentials authenticate SDK preflight reads; DC-to-DC replication
// uses the destination DC's replication identity, not forwarded credentials.
type SyncObjectRequest struct {
	Source       Config
	Object       SyncObjectIdentity
	Partition    string
	PasswordOnly bool
	// Properties verifies these complete, nonempty source value sets against
	// destination readback. Empty defaults to objectClass. This is an exact raw
	// byte multiset comparison, not schema equality or proof of all attributes.
	// Omitted/hidden/ranged values fail verification rather than proving absence.
	// PasswordOnly does not accept Properties and never reads password values.
	Properties []string
}

func (r SyncObjectRequest) Validate() error {
	if err := r.Source.Validate(); err != nil {
		return errors.Join(ErrInvalidObjectSync, err)
	}
	if !validDirectoryText(r.Partition) || r.Partition == "" || !strings.Contains(r.Partition, "=") {
		return ErrInvalidObjectSync
	}
	if (r.Object.DistinguishedName == "") == (len(r.Object.ObjectGUID) == 0) {
		return ErrInvalidObjectSync
	}
	if r.Object.DistinguishedName != "" && (!validDirectoryText(r.Object.DistinguishedName) || !strings.Contains(r.Object.DistinguishedName, "=") || strings.HasPrefix(r.Object.DistinguishedName, "<")) {
		return ErrInvalidObjectSync
	}
	if len(r.Object.ObjectGUID) != 0 && (len(r.Object.ObjectGUID) != 16 || bytes.Equal(r.Object.ObjectGUID, make([]byte, 16))) {
		return ErrInvalidObjectSync
	}
	if r.PasswordOnly && len(r.Properties) != 0 {
		return ErrInvalidObjectSync
	}
	for _, p := range r.Properties {
		if !attributeDescription.MatchString(p) || strings.Contains(p, ";") || p == "1.1" {
			return ErrInvalidProperty
		}
	}
	return nil
}

type ObjectSyncWriteState uint8

const (
	ObjectSyncNotAttempted ObjectSyncWriteState = iota
	ObjectSyncAccepted
	ObjectSyncRejected
	ObjectSyncUncertain
)

// SyncObjectResult preserves acknowledgement separately from verification.
// Accepted means the synchronous LDAP operation returned success. A rejected
// response is not a guarantee that every server-side step had no effect.
// Verified describes only Properties, or the unicodePwd cache marker for
// PasswordOnly. It never asserts forest-wide convergence or secret equality.
type SyncObjectResult struct {
	State               ObjectSyncWriteState
	SourceDSA           Object
	DestinationDSA      Object
	Partition           Object
	SourceObject        Object
	DestinationObject   Object
	VerifiedProperties  []string
	PasswordPolicy      *uint32
	SecretCacheObserved bool
	Verified            bool
}

// SyncObject invokes documented rootDSE replicateSingleObject exactly once.
// It first validates source/destination DSA, configuration and NC identities,
// the source object and destination parent. PasswordOnly requires a writable
// AD DS source, an RODC destination, and an allowed policy/control-access check.
// Permissions are ultimately checked by the server when executing the write.
// No referral, reconnect, automatic replay or forest synchronization is used.
// Cancellation/loss of response after submission is uncertain, even if abandon
// succeeds. Accepted remains accepted when later readback or cleanup fails.
func (c *Client) SyncObject(ctx context.Context, request SyncObjectRequest) (result SyncObjectResult, err error) {
	return c.syncObjectDial(ctx, request, Dial)
}

func (c *Client) syncObjectDial(ctx context.Context, request SyncObjectRequest, dial func(context.Context, Config) (*Client, error)) (result SyncObjectResult, err error) {
	if err = request.Validate(); err != nil {
		return result, err
	}
	request.Object.ObjectGUID = slices.Clone(request.Object.ObjectGUID)
	request.Properties = slices.Clone(request.Properties)
	err = c.read(ctx, func(bounded context.Context) error {
		writer, ok := c.session.(ldapModifySession)
		if !ok {
			return ErrUnsupported
		}
		source, openErr := dial(bounded, request.Source)
		if openErr != nil {
			return fmt.Errorf("source preflight: %w", openErr)
		}
		operationErr := source.read(bounded, func(sourceContext context.Context) error {
			return synchronizeObject(sourceContext, writer, source.session, request, &result)
		})
		return errors.Join(operationErr, source.Close())
	})
	return result, objectSyncError(err)
}

type objectSyncServer struct {
	root RootDSE
	dsa  Object
	rodc bool
}

func synchronizeObject(ctx context.Context, destination ldapModifySession, source directorySession, request SyncObjectRequest, result *SyncObjectResult) error {
	src, dst, err := prepareObjectSyncServers(ctx, destination, source, request, result)
	if err != nil {
		return err
	}
	if err := prepareObjectSyncPartition(ctx, destination, source, request, src, dst, result); err != nil {
		return err
	}
	properties, err := prepareObjectSyncObject(ctx, destination, source, request, src, result)
	if err != nil {
		return err
	}
	value := syncGUIDDN(syncGUID(src.dsa)) + ":" + syncGUIDDN(syncGUID(result.SourceObject))
	if request.PasswordOnly {
		if err := prepareObjectSyncPassword(ctx, destination, src, dst, result); err != nil {
			return err
		}
		value += ":SECRETS_ONLY"
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	attempt := destination.ldapModify(ctx, "", []ldapModification{{operation: 2, attribute: "replicateSingleObject", value: []byte(value)}})
	result.State = ObjectSyncWriteState(attempt.State)
	if attempt.State != ldapWriteAccepted {
		if attempt.State == ldapWriteUncertain {
			return errors.Join(ErrObjectSyncUncertain, attempt.Err)
		}
		if attempt.Err == nil {
			return ErrInvalidResult
		}
		return attempt.Err
	}
	return verifyObjectSync(ctx, destination, request, properties, result, attempt.Err)
}

func prepareObjectSyncServers(ctx context.Context, destination, source directorySession, request SyncObjectRequest, result *SyncObjectResult) (objectSyncServer, objectSyncServer, error) {
	var src, dst objectSyncServer
	src, err := readObjectSyncServer(ctx, source)
	result.SourceDSA = src.dsa
	if err != nil {
		return src, dst, fmt.Errorf("source: %w", err)
	}
	dst, err = readObjectSyncServer(ctx, destination)
	result.DestinationDSA = dst.dsa
	if err != nil {
		return src, dst, fmt.Errorf("destination: %w", err)
	}
	if src.root.Capabilities().Type != dst.root.Capabilities().Type || bytes.Equal(syncGUID(src.dsa), syncGUID(dst.dsa)) {
		return src, dst, ErrObjectSyncIdentity
	}
	if request.PasswordOnly && (src.root.Capabilities().Type != DirectoryADDS || src.rodc || !dst.rodc) {
		return src, dst, ErrObjectSyncCapability
	}
	return src, dst, nil
}

func prepareObjectSyncPartition(ctx context.Context, destination, source directorySession, request SyncObjectRequest, src, dst objectSyncServer, result *SyncObjectResult) error {
	// Match GUIDs rather than trusting names reused by unrelated forests.
	if _, err := matchingSyncObjects(ctx, source, destination, *src.root.ConfigurationNamingContext, *dst.root.ConfigurationNamingContext); err != nil {
		return err
	}
	partition, err := matchingSyncObjects(ctx, source, destination, request.Partition, request.Partition)
	result.Partition = partition
	if err != nil {
		return err
	}
	for _, session := range []directorySession{source, destination} {
		p, readErr := readSyncObject(ctx, session, syncGUIDDN(syncGUID(partition)), nil)
		d := rootDSEDecoder{attributes: p.Attributes}
		instance := decodeScalar(&d, "instanceType", parseUint32)
		if readErr != nil || len(d.errors) != 0 {
			return errors.Join(readErr, errors.Join(d.errors...))
		}
		// NC head required; coming/going replicas cannot establish readiness.
		if instance == nil || *instance&1 == 0 || *instance&0x30 != 0 {
			return ErrObjectSyncIdentity
		}
	}
	for _, server := range []objectSyncServer{src, dst} {
		if !slices.ContainsFunc(server.root.NamingContexts, func(n string) bool { return strings.EqualFold(n, partition.DistinguishedName) }) {
			return ErrObjectSyncIdentity
		}
		fullAttribute := "msds-hasmasterncs"
		if server.rodc {
			fullAttribute = "msds-hasfullreplicancs"
		}
		if !slices.ContainsFunc(server.dsa.Attributes[fullAttribute], func(n []byte) bool { return strings.EqualFold(string(n), partition.DistinguishedName) }) {
			return ErrObjectSyncCapability
		}
	}
	// The destination must know the exact source DSA in its configuration replica.
	if _, err := matchingSyncObjects(ctx, source, destination, syncGUIDDN(syncGUID(src.dsa)), syncGUIDDN(syncGUID(src.dsa))); err != nil {
		return err
	}
	return nil
}

func prepareObjectSyncObject(ctx context.Context, destination, source directorySession, request SyncObjectRequest, src objectSyncServer, result *SyncObjectResult) ([]string, error) {
	identity := request.Object.DistinguishedName
	if len(request.Object.ObjectGUID) != 0 {
		identity = syncGUIDDN(request.Object.ObjectGUID)
	}
	properties := slices.Clone(request.Properties)
	if len(properties) == 0 {
		properties = []string{"objectClass"}
	}
	object, err := readSyncObject(ctx, source, identity, properties)
	result.SourceObject = object
	if err != nil {
		return properties, err
	}
	if !syncObjectInNC(object.DistinguishedName, result.Partition.DistinguishedName, src.root.NamingContexts) {
		return properties, ErrObjectSyncIdentity
	}
	if len(request.Object.ObjectGUID) != 0 && !bytes.Equal(request.Object.ObjectGUID, syncGUID(object)) {
		return properties, ErrObjectSyncIdentity
	}
	if !request.PasswordOnly {
		for _, p := range properties {
			if values, state := object.Attribute(p); state != AttributePresent || len(values) == 0 {
				return properties, fmt.Errorf("%w: source property %s unavailable", ErrObjectSyncReadback, p)
			}
		}
	}
	if !bytes.Equal(syncGUID(object), syncGUID(result.Partition)) {
		parent, parentErr := parentDirectoryDN(object.DistinguishedName)
		if parentErr != nil {
			return properties, parentErr
		}
		if _, err = matchingSyncObjects(ctx, source, destination, parent, parent); err != nil {
			return properties, fmt.Errorf("destination parent: %w", err)
		}
	}
	return properties, nil
}

func prepareObjectSyncPassword(ctx context.Context, destination directorySession, src, dst objectSyncServer, result *SyncObjectResult) error {
	if !syncHasClass(result.SourceObject, "user") {
		return ErrObjectSyncCapability
	}
	if src.root.DefaultNamingContext == nil || dst.root.DefaultNamingContext == nil || !strings.EqualFold(result.Partition.DistinguishedName, *src.root.DefaultNamingContext) || !strings.EqualFold(result.Partition.DistinguishedName, *dst.root.DefaultNamingContext) {
		return ErrObjectSyncCapability
	}
	policy, ok := destination.(objectSyncPolicySession)
	if !ok || !slices.Contains(dst.root.SupportedControls, objectSyncDNInputOID) {
		return ErrObjectSyncCapability
	}
	attrs, policyErr := policy.objectSyncPasswordPolicy(ctx, syncGUIDDN(syncGUID(dst.dsa)), syncGUIDDN(syncGUID(result.SourceObject)))
	d := rootDSEDecoder{attributes: attrs}
	result.PasswordPolicy = decodeScalar(&d, "msDS-IsUserCachableAtRodc", parseUint32)
	if err := errors.Join(policyErr, errors.Join(d.errors...)); err != nil {
		return err
	}
	if result.PasswordPolicy == nil {
		return ErrObjectSyncCapability
	}
	if *result.PasswordPolicy != 1 {
		return ErrObjectSyncPasswordPolicy
	}
	return nil
}

func verifyObjectSync(ctx context.Context, destination directorySession, request SyncObjectRequest, properties []string, result *SyncObjectResult, writeErr error) error {
	// Read back only after a definite acknowledgement. A failed read cannot
	// change accepted into not-attempted and never causes another Modify.
	observed, readErr := readSyncObject(ctx, destination, syncGUIDDN(syncGUID(result.SourceObject)), properties)
	result.DestinationObject = observed
	if readErr != nil {
		return errors.Join(writeErr, ErrObjectSyncReadback, readErr)
	}
	if !bytes.Equal(syncGUID(result.SourceObject), syncGUID(observed)) {
		return errors.Join(writeErr, ErrObjectSyncReadback)
	}
	if request.PasswordOnly {
		result.SecretCacheObserved, readErr = observeObjectSyncSecret(ctx, destination, result.DestinationDSA, observed)
		result.Verified = readErr == nil && result.SecretCacheObserved
	} else {
		for _, property := range properties {
			want, _ := result.SourceObject.Attribute(property)
			got, state := observed.Attribute(property)
			if state != AttributePresent || !syncValuesEqual(want, got) {
				readErr = errors.Join(readErr, fmt.Errorf("%w: %s", ErrObjectSyncReadback, property))
				continue
			}
			result.VerifiedProperties = append(result.VerifiedProperties, property)
		}
		result.Verified = readErr == nil
	}
	if !result.Verified {
		readErr = errors.Join(ErrObjectSyncReadback, readErr)
	}
	return errors.Join(writeErr, readErr)
}

func readObjectSyncServer(ctx context.Context, session directorySession) (result objectSyncServer, err error) {
	attrs, err := session.baseObject(ctx, "", []string{"supportedCapabilities", "supportedControl", "dsServiceName", "configurationNamingContext", "defaultNamingContext", "namingContexts", "isSynchronized"})
	if err != nil {
		return result, err
	}
	result.root, err = decodeRootDSE(attrs, nil)
	if err != nil {
		return result, err
	}
	r := result.root
	if r.Capabilities().Type == DirectoryUnknown || r.DSServiceName == nil || r.ConfigurationNamingContext == nil || r.IsSynchronized == nil || !*r.IsSynchronized {
		return result, ErrObjectSyncCapability
	}
	result.dsa, err = readSyncObject(ctx, session, *r.DSServiceName, []string{"msDS-isRODC", "msDS-hasMasterNCs", "msDS-hasFullReplicaNCs"})
	if err != nil {
		return result, err
	}
	if !syncHasClass(result.dsa, "nTDSDSA") {
		return result, ErrObjectSyncIdentity
	}
	if r.Capabilities().Type == DirectoryADDS {
		d := rootDSEDecoder{attributes: result.dsa.Attributes}
		rodc := decodeScalar(&d, "msDS-isRODC", parseLDAPBool)
		if rodc == nil || len(d.errors) != 0 {
			return result, errors.Join(ErrObjectSyncCapability, errors.Join(d.errors...))
		}
		result.rodc = *rodc
	}
	return result, nil
}

func readSyncObject(ctx context.Context, session directorySession, dn string, properties []string) (Object, error) {
	attrs := append([]string{"distinguishedName", "objectGUID", "objectClass", "instanceType", "isDeleted"}, properties...)
	raw, err := session.baseObject(ctx, dn, attrs)
	o := Object{Attributes: raw, RequestedProperties: attrs}
	d := rootDSEDecoder{attributes: raw}
	name := d.text("distinguishedName")
	guid := copiedBinary(&d, "objectGUID", 16)
	deleted := decodeScalar(&d, "isDeleted", parseLDAPBool)
	if name != nil {
		o.DistinguishedName = *name
	}
	if err = errors.Join(err, errors.Join(d.errors...)); err != nil {
		return o, err
	}
	if name == nil || *name == "" || len(guid) != 16 || bytes.Equal(guid, make([]byte, 16)) || (deleted != nil && *deleted) {
		return o, ErrObjectSyncIdentity
	}
	return o, nil
}

func matchingSyncObjects(ctx context.Context, source, destination directorySession, sourceDN, destinationDN string) (Object, error) {
	a, err := readSyncObject(ctx, source, sourceDN, nil)
	if err != nil {
		return a, err
	}
	b, err := readSyncObject(ctx, destination, destinationDN, nil)
	if err != nil {
		return a, err
	}
	if !bytes.Equal(syncGUID(a), syncGUID(b)) {
		return a, ErrObjectSyncIdentity
	}
	return a, nil
}

func syncGUID(o Object) []byte {
	v := o.Attributes["objectguid"]
	if len(v) != 1 {
		return nil
	}
	return v[0]
}
func syncGUIDDN(guid []byte) string { return "<GUID=" + hex.EncodeToString(guid) + ">" }
func syncHasClass(o Object, class string) bool {
	return slices.ContainsFunc(o.Attributes["objectclass"], func(v []byte) bool { return strings.EqualFold(string(v), class) })
}
func syncObjectInNC(dn, partition string, contexts []string) bool {
	for dn != "" {
		if slices.ContainsFunc(contexts, func(n string) bool { return strings.EqualFold(n, dn) }) {
			return strings.EqualFold(dn, partition)
		}
		next, err := parentDirectoryDN(dn)
		if err != nil {
			return false
		}
		dn = next
	}
	return false
}
func syncValuesEqual(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	slices.SortFunc(x, bytes.Compare)
	slices.SortFunc(y, bytes.Compare)
	return slices.EqualFunc(x, y, bytes.Equal)
}
func objectSyncError(err error) error {
	var ldapErr *LDAPError
	if errors.As(err, &ldapErr) && ldapErr.Code == 50 {
		return errors.Join(ErrObjectSyncPermission, err)
	}
	return err
}

const objectSyncDNInputOID = "1.2.840.113556.1.4.2026"

type objectSyncPolicySession interface {
	objectSyncPasswordPolicy(context.Context, string, string) (map[string][][]byte, error)
}

func observeObjectSyncSecret(ctx context.Context, session directorySession, dsa, account Object) (bool, error) {
	serverDN, err := parentDirectoryDN(dsa.DistinguishedName)
	if err != nil {
		return false, err
	}
	attrs, err := session.baseObject(ctx, serverDN, []string{"serverReference"})
	d := rootDSEDecoder{attributes: attrs}
	computerDN := d.text("serverReference")
	if err = errors.Join(err, errors.Join(d.errors...)); err != nil {
		return false, err
	}
	if computerDN == nil {
		return false, ErrInvalidResult
	}
	attrs, err = session.baseObject(ctx, *computerDN, []string{"msDS-RevealedList"})
	if err != nil {
		return false, err
	}
	for _, value := range attrs["msds-revealedlist"] {
		// MS-ADTS DN-String: S:<character count>:<attribute name>:<DN>.
		// unicodePwd is ASCII, so its 10 characters are also 10 octets.
		const prefix = "S:10:unicodePwd:"
		if strings.HasPrefix(strings.ToLower(string(value)), strings.ToLower(prefix)) {
			cached, readErr := readSyncObject(ctx, session, string(value[len(prefix):]), nil)
			if readErr != nil {
				return false, readErr
			}
			if bytes.Equal(syncGUID(cached), syncGUID(account)) {
				return true, nil
			}
		}
	}
	return false, nil
}

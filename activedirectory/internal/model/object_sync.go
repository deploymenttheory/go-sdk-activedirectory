package model

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
	ErrInvalidObjectSync    = errors.New("invalid single-object synchronization request")
	ErrObjectSyncCapability = errors.New(
		"server cannot perform the requested object synchronization",
	)
	ErrObjectSyncIdentity = errors.New(
		"object synchronization identities or naming contexts do not match",
	)
	ErrObjectSyncPermission     = errors.New("object synchronization access denied")
	ErrObjectSyncPasswordPolicy = errors.New(
		"RODC password replication policy does not allow this account",
	)
	ErrObjectSyncUncertain = errors.New(
		"object synchronization outcome is unknown; reconcile before another write",
	)
	ErrObjectSyncReadback = errors.New(
		"object synchronization readback did not verify the requested observation",
	)
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
	if !InternalValidDirectoryText(r.Partition) || r.Partition == "" ||
		!strings.Contains(r.Partition, "=") {
		return ErrInvalidObjectSync
	}
	if (r.Object.DistinguishedName == "") == (len(r.Object.ObjectGUID) == 0) {
		return ErrInvalidObjectSync
	}
	if r.Object.DistinguishedName != "" &&
		(!InternalValidDirectoryText(r.Object.DistinguishedName) || !strings.Contains(r.Object.DistinguishedName, "=") || strings.HasPrefix(r.Object.DistinguishedName, "<")) {
		return ErrInvalidObjectSync
	}
	if len(r.Object.ObjectGUID) != 0 &&
		(len(r.Object.ObjectGUID) != 16 || bytes.Equal(r.Object.ObjectGUID, make([]byte, 16))) {
		return ErrInvalidObjectSync
	}
	if r.PasswordOnly && len(r.Properties) != 0 {
		return ErrInvalidObjectSync
	}
	for _, p := range r.Properties {
		if !InternalAttributeDescription.MatchString(p) || strings.Contains(p, ";") || p == "1.1" {
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

type InternalObjectSyncServer struct {
	InternalRoot RootDSE
	InternalDsa  Object
	InternalRodc bool
}

func InternalSynchronizeObject(
	ctx context.Context,
	destination InternalLdapModifySession,
	source InternalDirectorySession,
	request SyncObjectRequest,
	result *SyncObjectResult,
) error {
	src, dst, err := InternalPrepareObjectSyncServers(ctx, destination, source, request, result)
	if err != nil {
		return err
	}
	if err := InternalPrepareObjectSyncPartition(
		ctx,
		destination,
		source,
		request,
		src,
		dst,
		result,
	); err != nil {
		return err
	}
	properties, err := InternalPrepareObjectSyncObject(
		ctx,
		destination,
		source,
		request,
		src,
		result,
	)
	if err != nil {
		return err
	}
	value := InternalSyncGUIDDN(
		InternalSyncGUID(src.InternalDsa),
	) + ":" + InternalSyncGUIDDN(
		InternalSyncGUID(result.SourceObject),
	)
	if request.PasswordOnly {
		if err := InternalPrepareObjectSyncPassword(
			ctx,
			destination,
			src,
			dst,
			result,
		); err != nil {
			return err
		}
		value += ":SECRETS_ONLY"
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	attempt := destination.InternalLdapModify(
		ctx,
		"",
		[]InternalLdapModification{
			{
				InternalOperation: 2,
				InternalAttribute: "replicateSingleObject",
				InternalValue:     []byte(value),
			},
		},
	)
	result.State = ObjectSyncWriteState(attempt.State)
	if attempt.State != InternalLdapWriteAccepted {
		if attempt.State == InternalLdapWriteUncertain {
			return errors.Join(ErrObjectSyncUncertain, attempt.Err)
		}
		if attempt.Err == nil {
			return ErrInvalidResult
		}
		return attempt.Err
	}
	return InternalVerifyObjectSync(ctx, destination, request, properties, result, attempt.Err)
}

func InternalPrepareObjectSyncServers(
	ctx context.Context,
	destination, source InternalDirectorySession,
	request SyncObjectRequest,
	result *SyncObjectResult,
) (InternalObjectSyncServer, InternalObjectSyncServer, error) {
	var src, dst InternalObjectSyncServer
	src, err := InternalReadObjectSyncServer(ctx, source)
	result.SourceDSA = src.InternalDsa
	if err != nil {
		return src, dst, fmt.Errorf("source: %w", err)
	}
	dst, err = InternalReadObjectSyncServer(ctx, destination)
	result.DestinationDSA = dst.InternalDsa
	if err != nil {
		return src, dst, fmt.Errorf("destination: %w", err)
	}
	if src.InternalRoot.Capabilities().Type != dst.InternalRoot.Capabilities().Type ||
		bytes.Equal(InternalSyncGUID(src.InternalDsa), InternalSyncGUID(dst.InternalDsa)) {
		return src, dst, ErrObjectSyncIdentity
	}
	if request.PasswordOnly &&
		(src.InternalRoot.Capabilities().Type != DirectoryADDS || src.InternalRodc || !dst.InternalRodc) {
		return src, dst, ErrObjectSyncCapability
	}
	return src, dst, nil
}

func InternalPrepareObjectSyncPartition(
	ctx context.Context,
	destination, source InternalDirectorySession,
	request SyncObjectRequest,
	src, dst InternalObjectSyncServer,
	result *SyncObjectResult,
) error {
	// Match GUIDs rather than trusting names reused by unrelated forests.
	if _, err := InternalMatchingSyncObjects(
		ctx,
		source,
		destination,
		*src.InternalRoot.ConfigurationNamingContext,
		*dst.InternalRoot.ConfigurationNamingContext,
	); err != nil {
		return err
	}
	partition, err := InternalMatchingSyncObjects(
		ctx,
		source,
		destination,
		request.Partition,
		request.Partition,
	)
	result.Partition = partition
	if err != nil {
		return err
	}
	for _, session := range []InternalDirectorySession{source, destination} {
		p, readErr := InternalReadSyncObject(
			ctx,
			session,
			InternalSyncGUIDDN(InternalSyncGUID(partition)),
			nil,
		)
		d := InternalRootDSEDecoder{InternalAttributes: p.Attributes}
		instance := InternalDecodeScalar(&d, "instanceType", InternalParseUint32)
		if readErr != nil || len(d.InternalErrors) != 0 {
			return errors.Join(readErr, errors.Join(d.InternalErrors...))
		}
		// NC head required; coming/going replicas cannot establish readiness.
		if instance == nil || *instance&1 == 0 || *instance&0x30 != 0 {
			return ErrObjectSyncIdentity
		}
	}
	for _, server := range []InternalObjectSyncServer{src, dst} {
		if !slices.ContainsFunc(
			server.InternalRoot.NamingContexts,
			func(n string) bool { return strings.EqualFold(n, partition.DistinguishedName) },
		) {
			return ErrObjectSyncIdentity
		}
		fullAttribute := "msds-hasmasterncs"
		if server.InternalRodc {
			fullAttribute = "msds-hasfullreplicancs"
		}
		if !slices.ContainsFunc(
			server.InternalDsa.Attributes[fullAttribute],
			func(n []byte) bool { return strings.EqualFold(string(n), partition.DistinguishedName) },
		) {
			return ErrObjectSyncCapability
		}
	}
	// The destination must know the exact source DSA in its configuration replica.
	if _, err := InternalMatchingSyncObjects(
		ctx,
		source,
		destination,
		InternalSyncGUIDDN(InternalSyncGUID(src.InternalDsa)),
		InternalSyncGUIDDN(InternalSyncGUID(src.InternalDsa)),
	); err != nil {
		return err
	}
	return nil
}

func InternalPrepareObjectSyncObject(
	ctx context.Context,
	destination, source InternalDirectorySession,
	request SyncObjectRequest,
	src InternalObjectSyncServer,
	result *SyncObjectResult,
) ([]string, error) {
	identity := request.Object.DistinguishedName
	if len(request.Object.ObjectGUID) != 0 {
		identity = InternalSyncGUIDDN(request.Object.ObjectGUID)
	}
	properties := slices.Clone(request.Properties)
	if len(properties) == 0 {
		properties = []string{"objectClass"}
	}
	object, err := InternalReadSyncObject(ctx, source, identity, properties)
	result.SourceObject = object
	if err != nil {
		return properties, err
	}
	if !InternalSyncObjectInNC(
		object.DistinguishedName,
		result.Partition.DistinguishedName,
		src.InternalRoot.NamingContexts,
	) {
		return properties, ErrObjectSyncIdentity
	}
	if len(request.Object.ObjectGUID) != 0 &&
		!bytes.Equal(request.Object.ObjectGUID, InternalSyncGUID(object)) {
		return properties, ErrObjectSyncIdentity
	}
	if !request.PasswordOnly {
		for _, p := range properties {
			if values, state := object.Attribute(p); state != AttributePresent || len(values) == 0 {
				return properties, fmt.Errorf(
					"%w: source property %s unavailable",
					ErrObjectSyncReadback,
					p,
				)
			}
		}
	}
	if !bytes.Equal(InternalSyncGUID(object), InternalSyncGUID(result.Partition)) {
		parent, parentErr := InternalParentDirectoryDN(object.DistinguishedName)
		if parentErr != nil {
			return properties, parentErr
		}
		if _, err = InternalMatchingSyncObjects(
			ctx,
			source,
			destination,
			parent,
			parent,
		); err != nil {
			return properties, fmt.Errorf("destination parent: %w", err)
		}
	}
	return properties, nil
}

func InternalPrepareObjectSyncPassword(
	ctx context.Context,
	destination InternalDirectorySession,
	src, dst InternalObjectSyncServer,
	result *SyncObjectResult,
) error {
	if !InternalSyncHasClass(result.SourceObject, "user") {
		return ErrObjectSyncCapability
	}
	if src.InternalRoot.DefaultNamingContext == nil ||
		dst.InternalRoot.DefaultNamingContext == nil ||
		!strings.EqualFold(
			result.Partition.DistinguishedName,
			*src.InternalRoot.DefaultNamingContext,
		) ||
		!strings.EqualFold(
			result.Partition.DistinguishedName,
			*dst.InternalRoot.DefaultNamingContext,
		) {
		return ErrObjectSyncCapability
	}
	policy, ok := destination.(InternalObjectSyncPolicySession)
	if !ok || !slices.Contains(dst.InternalRoot.SupportedControls, InternalObjectSyncDNInputOID) {
		return ErrObjectSyncCapability
	}
	attrs, policyErr := policy.InternalObjectSyncPasswordPolicy(
		ctx,
		InternalSyncGUIDDN(InternalSyncGUID(dst.InternalDsa)),
		InternalSyncGUIDDN(InternalSyncGUID(result.SourceObject)),
	)
	d := InternalRootDSEDecoder{InternalAttributes: attrs}
	result.PasswordPolicy = InternalDecodeScalar(
		&d,
		"msDS-IsUserCachableAtRodc",
		InternalParseUint32,
	)
	if err := errors.Join(policyErr, errors.Join(d.InternalErrors...)); err != nil {
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

func InternalVerifyObjectSync(
	ctx context.Context,
	destination InternalDirectorySession,
	request SyncObjectRequest,
	properties []string,
	result *SyncObjectResult,
	writeErr error,
) error {
	// Read back only after a definite acknowledgement. A failed read cannot
	// change accepted into not-attempted and never causes another Modify.
	observed, readErr := InternalReadSyncObject(
		ctx,
		destination,
		InternalSyncGUIDDN(InternalSyncGUID(result.SourceObject)),
		properties,
	)
	result.DestinationObject = observed
	if readErr != nil {
		return errors.Join(writeErr, ErrObjectSyncReadback, readErr)
	}
	if !bytes.Equal(InternalSyncGUID(result.SourceObject), InternalSyncGUID(observed)) {
		return errors.Join(writeErr, ErrObjectSyncReadback)
	}
	if request.PasswordOnly {
		result.SecretCacheObserved, readErr = InternalObserveObjectSyncSecret(
			ctx,
			destination,
			result.DestinationDSA,
			observed,
		)
		result.Verified = readErr == nil && result.SecretCacheObserved
	} else {
		for _, property := range properties {
			want, _ := result.SourceObject.Attribute(property)
			got, state := observed.Attribute(property)
			if state != AttributePresent || !InternalSyncValuesEqual(want, got) {
				readErr = errors.Join(
					readErr,
					fmt.Errorf("%w: %s", ErrObjectSyncReadback, property),
				)
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

func InternalReadObjectSyncServer(
	ctx context.Context,
	session InternalDirectorySession,
) (result InternalObjectSyncServer, err error) {
	attrs, err := session.InternalBaseObject(
		ctx,
		"",
		[]string{
			"supportedCapabilities",
			"supportedControl",
			"dsServiceName",
			"configurationNamingContext",
			"defaultNamingContext",
			"namingContexts",
			"isSynchronized",
		},
	)
	if err != nil {
		return result, err
	}
	result.InternalRoot, err = InternalDecodeRootDSE(attrs, nil)
	if err != nil {
		return result, err
	}
	r := result.InternalRoot
	if r.Capabilities().Type == DirectoryUnknown || r.DSServiceName == nil ||
		r.ConfigurationNamingContext == nil ||
		r.IsSynchronized == nil ||
		!*r.IsSynchronized {
		return result, ErrObjectSyncCapability
	}
	result.InternalDsa, err = InternalReadSyncObject(
		ctx,
		session,
		*r.DSServiceName,
		[]string{"msDS-isRODC", "msDS-hasMasterNCs", "msDS-hasFullReplicaNCs"},
	)
	if err != nil {
		return result, err
	}
	if !InternalSyncHasClass(result.InternalDsa, "nTDSDSA") {
		return result, ErrObjectSyncIdentity
	}
	if r.Capabilities().Type == DirectoryADDS {
		d := InternalRootDSEDecoder{InternalAttributes: result.InternalDsa.Attributes}
		rodc := InternalDecodeScalar(&d, "msDS-isRODC", InternalParseLDAPBool)
		if rodc == nil || len(d.InternalErrors) != 0 {
			return result, errors.Join(ErrObjectSyncCapability, errors.Join(d.InternalErrors...))
		}
		result.InternalRodc = *rodc
	}
	return result, nil
}

func InternalReadSyncObject(
	ctx context.Context,
	session InternalDirectorySession,
	dn string,
	properties []string,
) (Object, error) {
	attrs := append(
		[]string{"distinguishedName", "objectGUID", "objectClass", "instanceType", "isDeleted"},
		properties...)
	raw, err := session.InternalBaseObject(ctx, dn, attrs)
	o := Object{Attributes: raw, RequestedProperties: attrs}
	d := InternalRootDSEDecoder{InternalAttributes: raw}
	name := d.InternalText("distinguishedName")
	guid := InternalCopiedBinary(&d, "objectGUID", 16)
	deleted := InternalDecodeScalar(&d, "isDeleted", InternalParseLDAPBool)
	if name != nil {
		o.DistinguishedName = *name
	}
	if err = errors.Join(err, errors.Join(d.InternalErrors...)); err != nil {
		return o, err
	}
	if name == nil || *name == "" || len(guid) != 16 || bytes.Equal(guid, make([]byte, 16)) ||
		(deleted != nil && *deleted) {
		return o, ErrObjectSyncIdentity
	}
	return o, nil
}

func InternalMatchingSyncObjects(
	ctx context.Context,
	source, destination InternalDirectorySession,
	sourceDN, destinationDN string,
) (Object, error) {
	a, err := InternalReadSyncObject(ctx, source, sourceDN, nil)
	if err != nil {
		return a, err
	}
	b, err := InternalReadSyncObject(ctx, destination, destinationDN, nil)
	if err != nil {
		return a, err
	}
	if !bytes.Equal(InternalSyncGUID(a), InternalSyncGUID(b)) {
		return a, ErrObjectSyncIdentity
	}
	return a, nil
}

func InternalSyncGUID(o Object) []byte {
	v := o.Attributes["objectguid"]
	if len(v) != 1 {
		return nil
	}
	return v[0]
}
func InternalSyncGUIDDN(guid []byte) string { return "<GUID=" + hex.EncodeToString(guid) + ">" }
func InternalSyncHasClass(o Object, class string) bool {
	return slices.ContainsFunc(
		o.Attributes["objectclass"],
		func(v []byte) bool { return strings.EqualFold(string(v), class) },
	)
}

func InternalSyncObjectInNC(dn, partition string, contexts []string) bool {
	for dn != "" {
		if slices.ContainsFunc(contexts, func(n string) bool { return strings.EqualFold(n, dn) }) {
			return strings.EqualFold(dn, partition)
		}
		next, err := InternalParentDirectoryDN(dn)
		if err != nil {
			return false
		}
		dn = next
	}
	return false
}

func InternalSyncValuesEqual(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	slices.SortFunc(x, bytes.Compare)
	slices.SortFunc(y, bytes.Compare)
	return slices.EqualFunc(x, y, bytes.Equal)
}

func InternalObjectSyncError(err error) error {
	var ldapErr *LDAPError
	if errors.As(err, &ldapErr) && ldapErr.Code == 50 {
		return errors.Join(ErrObjectSyncPermission, err)
	}
	return err
}

const InternalObjectSyncDNInputOID = "1.2.840.113556.1.4.2026"

type InternalObjectSyncPolicySession interface {
	InternalObjectSyncPasswordPolicy(context.Context, string, string) (map[string][][]byte, error)
}

func InternalObserveObjectSyncSecret(
	ctx context.Context,
	session InternalDirectorySession,
	dsa, account Object,
) (bool, error) {
	serverDN, err := InternalParentDirectoryDN(dsa.DistinguishedName)
	if err != nil {
		return false, err
	}
	attrs, err := session.InternalBaseObject(ctx, serverDN, []string{"serverReference"})
	d := InternalRootDSEDecoder{InternalAttributes: attrs}
	computerDN := d.InternalText("serverReference")
	if err = errors.Join(err, errors.Join(d.InternalErrors...)); err != nil {
		return false, err
	}
	if computerDN == nil {
		return false, ErrInvalidResult
	}
	attrs, err = session.InternalBaseObject(ctx, *computerDN, []string{"msDS-RevealedList"})
	if err != nil {
		return false, err
	}
	for _, value := range attrs["msds-revealedlist"] {
		// MS-ADTS DN-String: S:<character count>:<attribute name>:<DN>.
		// unicodePwd is ASCII, so its 10 characters are also 10 octets.
		const prefix = "S:10:unicodePwd:"
		if strings.HasPrefix(strings.ToLower(string(value)), strings.ToLower(prefix)) {
			markerDN := string(value[len(prefix):])
			// Both DNs are canonical observations from this destination. Do not
			// resolve unrelated cached principals: they may be hidden/deleted,
			// and their readability cannot establish this account's cache state.
			// A concurrent rename can leave verification incomplete; never use
			// an unrelated marker or replay the accepted write to compensate.
			if !strings.EqualFold(markerDN, account.DistinguishedName) {
				continue
			}
			cached, readErr := InternalReadSyncObject(ctx, session, markerDN, nil)
			if readErr != nil {
				return false, readErr
			}
			if bytes.Equal(InternalSyncGUID(cached), InternalSyncGUID(account)) {
				return true, nil
			}
		}
	}
	return false, nil
}

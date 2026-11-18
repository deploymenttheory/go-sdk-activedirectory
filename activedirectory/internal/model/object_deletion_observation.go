package model

import (
	"context"
	"errors"
	"slices"
)

func internalObserveDeletedObjectProof(ctx context.Context, session InternalDirectorySession, root RootDSE, result *ObjectMutationResult) error {
	if result.TargetGUID == nil || result.Partition == "" {
		return errors.Join(ErrObjectUnverifiable, ErrInvalidResult)
	}
	// ShowRecycled also includes ordinary deleted objects and tombstones. Select
	// the strongest advertised visibility once; never retry a refused control.
	controls, err := InternalRestorationControls(root, slices.Contains(root.SupportedControls, InternalObjectShowRecycledControl), false)
	if err != nil {
		return errors.Join(ErrObjectUnverifiable, err)
	}
	controlled := InternalControlledSearchSession{InternalDirectorySession: session, InternalControls: controls}
	search, err := InternalSearchIdentitySession(ctx, controlled, SearchOptions{
		// MS-ADTS3.1.1.3.1.2.4 permits an alternate GUID as baseObject.
		// An exact BASE read avoids unrelated subordinate-NC references. Do not
		// retry another base or reinterpret any incomplete result as complete.
		Base: InternalObjectGUIDTarget(*result.TargetGUID), Scope: ScopeBase,
		Filter:     "(&(objectGUID=" + InternalIdentityBinaryLiteral(result.TargetGUID.Bytes()) + ")(isDeleted=TRUE))",
		Properties: []string{"objectGUID", "isDeleted", "isRecycled", "lastKnownParent", "distinguishedName"}, PageSize: 2, ResultLimit: 2,
	})
	result.DeletionReadback = &search
	if err != nil {
		return errors.Join(ErrObjectReadback, err)
	}
	if !search.Complete {
		return errors.Join(ErrObjectReadback, ErrIncompleteResult)
	}
	if len(search.Objects) == 0 {
		return ErrObjectUnverifiable
	}
	if len(search.Objects) != 1 {
		return errors.Join(ErrObjectReadback, ErrInvalidResult)
	}
	object := search.Objects[0]
	dn, dnErr := InternalParseIdentityDN(object.DistinguishedName)
	selected, contexts, partitionErr := InternalIdentityPartition(InternalObjectGUIDIdentity(*result.TargetGUID), result.Partition, root)
	// A DN suffix alone admits subordinate naming contexts. Use the same
	// longest advertised context selection as ordinary identity resolution.
	if dnErr != nil || partitionErr != nil || InternalIdentityNamingContext(dn, contexts) != selected {
		return errors.Join(ErrObjectReadback, ErrIdentityScope, dnErr, partitionErr)
	}
	value, err := object.Values("objectGUID").Single()
	if err != nil {
		return errors.Join(ErrObjectReadback, ErrInvalidResult, err)
	}
	guid, err := value.GUID()
	if err != nil || guid != *result.TargetGUID {
		return errors.Join(ErrObjectReadback, ErrInvalidResult, err)
	}
	decoder := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	deleted := InternalDecodeScalar(&decoder, "isDeleted", InternalParseLDAPBool)
	if deleted == nil || !*deleted || len(decoder.InternalErrors) != 0 {
		return errors.Join(ErrObjectReadback, ErrInvalidResult, errors.Join(decoder.InternalErrors...))
	}
	result.Verified = true
	return nil
}

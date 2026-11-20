package engine

import (
	"context"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

var _ admodel.InternalGroupMemberReader = (*InternalPortableSession)(nil)

// InternalGroupMemberBaseObject reads direct-member ranges on the existing protected portable session.
// TTL selection sends the same critical control as the native reader; partial attributes and errors remain observable.
func (s *InternalPortableSession) InternalGroupMemberBaseObject(
	ctx context.Context, base string, attributes []string, ttl bool,
) (map[string][][]byte, error) {
	var controls []admodel.InternalLdapWriteControl
	if ttl {
		controls = []admodel.InternalLdapWriteControl{{InternalOid: admodel.InternalGroupLinkTTL, InternalCritical: true}}
	}
	object, err := s.internalReadBaseObject(ctx, base, attributes, true, controls)
	return object.Attributes, err
}

package engine

import (
	"context"
	"errors"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// InternalLdapWrite validates locally and submits exactly once. Only a valid
// response proves acceptance/refusal; an interrupted submitted effect is unknown.
func (s *InternalPortableSession) InternalLdapWrite(ctx context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
	if err := InternalValidateLDAPWrite(request); err != nil {
		return admodel.InternalLdapWriteAttempt{Err: err}
	}
	attempt := admodel.InternalLdapWriteAttempt{}
	attempt.Err = s.invoke(ctx, "write", func() error {
		// Entering the single submission call is conservative: any lost response
		// leaves the effect uncertain, including zero-byte connection failures.
		attempt.State = admodel.InternalLdapWriteUncertain
		err := s.write(request)
		if err == nil {
			attempt.State = admodel.InternalLdapWriteAccepted
		} else if internalPortableServerRefusal(err) {
			attempt.State = admodel.InternalLdapWriteRejected
		}
		return err
	})
	if attempt.State == admodel.InternalLdapWriteUncertain {
		attempt.Err = errors.Join(attempt.Err, admodel.InternalLDAPWriteUncertainError(), s.InternalClose())
	}
	return attempt
}

func (s *InternalPortableSession) write(request admodel.InternalLdapWriteRequest) error {
	controls := internalPortableControls(request.InternalControls)
	switch request.InternalOperation {
	case admodel.InternalLdapWriteAdd:
		add := ldap.NewAddRequest(request.InternalDn, controls)
		for _, modification := range request.InternalModifications {
			add.Attribute(modification.InternalAttribute, internalPortableStrings(modification.InternalValues))
		}
		return s.ldap.Add(add)
	case admodel.InternalLdapWriteModify:
		modify := ldap.NewModifyRequest(request.InternalDn, controls)
		for _, modification := range request.InternalModifications {
			values := internalPortableStrings(modification.InternalValues)
			switch modification.InternalOperation {
			case 0:
				modify.Add(modification.InternalAttribute, values)
			case 1:
				modify.Delete(modification.InternalAttribute, values)
			case 2:
				modify.Replace(modification.InternalAttribute, values)
			}
		}
		return s.ldap.Modify(modify)
	case admodel.InternalLdapWriteDelete:
		return s.ldap.Del(ldap.NewDelRequest(request.InternalDn, controls))
	case admodel.InternalLdapWriteRename:
		return s.ldap.ModifyDN(ldap.NewModifyDNWithControlsRequest(request.InternalDn, request.InternalNewRDN, request.InternalDeleteOldRDN, request.InternalNewParent, controls))
	}
	return admodel.ErrInvalidResult
}

// Go string conversion preserves arbitrary octets, including NUL and invalid
// UTF-8. The vendored encoder writes them as OCTET STRING without conversion.
func internalPortableStrings(values [][]byte) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = string(value)
	}
	return result
}

func (s *InternalPortableSession) InternalLdapModify(ctx context.Context, dn string, modifications []admodel.InternalLdapModification) admodel.InternalLdapWriteAttempt {
	request := admodel.InternalLdapWriteRequest{
		InternalOperation:     admodel.InternalLdapWriteModify,
		InternalDn:            dn,
		InternalModifications: make([]admodel.InternalLdapAttributeModification, len(modifications)),
	}
	for i, modification := range modifications {
		request.InternalModifications[i] = admodel.InternalLdapAttributeModification{
			InternalOperation: modification.InternalOperation,
			InternalAttribute: modification.InternalAttribute,
			InternalValues:    [][]byte{modification.InternalValue},
		}
	}
	return s.InternalLdapWrite(ctx, request)
}

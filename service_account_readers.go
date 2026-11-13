package activedirectory

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"slices"
)

// Keep the full self-relative header and every non-DACL component. The DACL
// itself is encoded by the existing native codec. All buffers are Go-owned.
// This differs from an nTSecurityDescriptor SD-flags write: an attribute of
// security-descriptor syntax replaces the entire value.
func preserveDirectoryDescriptor(raw, encodedDACL []byte) ([]byte, error) {
	if _, err := decodeDirectoryDACL(raw); err != nil {
		return nil, err
	}
	if _, err := decodeDirectoryDACL(encodedDACL); err != nil {
		return nil, err
	}
	output := slices.Clone(raw[:20])
	for _, at := range []int{4, 8, 12, 16} {
		source := raw
		if at == 16 {
			source = encodedDACL
		}
		offset := int(binary.LittleEndian.Uint32(source[at : at+4]))
		binary.LittleEndian.PutUint32(output[at:at+4], 0)
		if offset == 0 {
			continue
		}
		length := 8 + 4*int(source[offset+1])
		if at >= 12 {
			length = int(binary.LittleEndian.Uint16(source[offset+2 : offset+4]))
		}
		binary.LittleEndian.PutUint32(output[at:at+4], uint32(len(output)))
		output = append(output, source[offset:offset+length]...)
	}
	return output, nil
}

func serviceAccountReaderACE(ace []byte) (SID, bool) {
	if len(ace) < 16 || ace[0] != 0 || ace[1] != 0 || binary.LittleEndian.Uint32(ace[4:8])&0x10 == 0 {
		return SID{}, false
	}
	sid, err := SIDFromBytes(ace[8:])
	return sid, err == nil
}
func serviceAccountDescriptorReaders(raw []byte) ([]SID, error) {
	acl, err := decodeDirectoryDACL(raw)
	if err != nil {
		return nil, err
	}
	var readers []SID
	for _, ace := range acl.aces {
		if sid, ok := serviceAccountReaderACE(ace); ok {
			if !slices.ContainsFunc(readers, func(s SID) bool { return bytes.Equal(s.Bytes(), sid.Bytes()) }) {
				readers = append(readers, sid)
			}
		}
	}
	return readers, nil
}
func serviceAccountReaderACEs(raw []byte, readers []SID) ([][]byte, error) {
	acl, err := decodeDirectoryDACL(raw)
	if err != nil {
		return nil, err
	}
	var aces [][]byte
	for _, ace := range acl.aces {
		if _, ok := serviceAccountReaderACE(ace); ok {
			mask := binary.LittleEndian.Uint32(ace[4:8]) &^ uint32(0x10)
			if mask == 0 {
				continue
			}
			ace = slices.Clone(ace)
			binary.LittleEndian.PutUint32(ace[4:8], mask)
		}
		aces = append(aces, ace)
	}
	// Insert explicit allows before inherited ACEs, retaining all original
	// relative ordering and all unrelated masks/opaque ACE bytes.
	index := len(aces)
	for i, ace := range aces {
		if ace[1]&0x10 != 0 {
			index = i
			break
		}
	}
	var grants [][]byte
	seen := map[string]bool{}
	for _, sid := range readers {
		data := sid.Bytes()
		if _, err := SIDFromBytes(data); err != nil {
			return nil, err
		}
		if seen[sid.String()] {
			continue
		}
		seen[sid.String()] = true
		ace := make([]byte, 8+len(data))
		binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
		binary.LittleEndian.PutUint32(ace[4:8], 0x10)
		copy(ace[8:], data)
		grants = append(grants, ace)
	}
	return slices.Insert(aces, index, grants...), nil
}
func replaceServiceAccountReaders(session directorySession, raw []byte, readers []SID) ([]byte, error) {
	aces, err := serviceAccountReaderACEs(raw, readers)
	if err != nil {
		return nil, err
	}
	encoder, ok := session.(interface {
		encodeDACL([]byte, [][]byte) ([]byte, error)
	})
	if !ok {
		return nil, ErrUnsupported
	}
	dacl, err := encoder.encodeDACL(raw, aces)
	if err != nil {
		return nil, err
	}
	return preserveDirectoryDescriptor(raw, dacl)
}

// The observation accompanies failures, including invalid class/SID and ACL
// omission. No unresolved principal is converted into a grant.
type ServiceAccountPrincipalError struct {
	Identity    Identity
	Observation IdentityResult
	Cause       error
}

func (e *ServiceAccountPrincipalError) Error() string {
	return "invalid managed-password retrieval principal: " + e.Cause.Error()
}
func (e *ServiceAccountPrincipalError) Unwrap() error { return e.Cause }
func resolveServiceAccountReaders(ctx context.Context, session directorySession, config Config, root RootDSE, identities []Identity, partition string) ([]SID, error) {
	if len(identities) > serviceAccountMaxLinks {
		return nil, ErrInvalidServiceAccount
	}
	var sids []SID
	for _, identity := range identities {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		options := accountControlIdentity(identity, partition, []string{"objectSid", "objectClass", "groupType"})
		options.Target = IdentityTargetAccount
		observation, err := resolveIdentitySession(ctx, session, config, root, identity, options)
		if err == nil {
			value, e := observation.Object.Values("objectSid").Single()
			err = e
			if err == nil {
				sid, e := value.SID()
				err = e
				if err == nil {
					sids = append(sids, sid)
				}
			}
		}
		if err != nil {
			return nil, &ServiceAccountPrincipalError{Identity: identity, Observation: observation, Cause: errors.Join(ErrInvalidServiceAccount, err)}
		}
	}
	return sids, nil
}

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

// CentralAccessReferenceLimits are per-source budgets. Zero selects a default;
// positive values override that default (they are not capped at the default).
type CentralAccessReferenceLimits struct{ MaxReferences, MaxRanges, MaxBytes int }
type CentralAccessReference struct {
	DistinguishedName string
	Raw               RawValue
}
type CentralAccessReferenceRange struct {
	RequestedProperty string
	Attributes        map[string][][]byte
	Error             error
}

// Complete means contiguous retrieval at one observed source GUID/USN. It does
// not prove ACL visibility or a snapshot across the referenced objects.
type CentralAccessReferencesResult struct {
	References                  []CentralAccessReference
	Ranges                      []CentralAccessReferenceRange
	AttributeReturned, Complete bool
	Error                       error
}
type centralAccessRangedSession interface {
	rangedBaseObject(context.Context, string, []string) (map[string][][]byte, error)
}

func normalizeCentralAccessLimits(limits CentralAccessReferenceLimits) (CentralAccessReferenceLimits, error) {
	if limits.MaxReferences < 0 || limits.MaxRanges < 0 || limits.MaxBytes < 0 {
		return limits, ErrCentralAccessReferences
	}
	if limits.MaxReferences == 0 {
		limits.MaxReferences = 100000
	}
	if limits.MaxRanges == 0 {
		limits.MaxRanges = 1000
	}
	if limits.MaxBytes == 0 {
		limits.MaxBytes = 64 << 20
	}
	return limits, nil
}
func centralAccessVersion(object Object) (GUID, uint64, error) {
	guid, err := centralAccessGUID(object)
	if err != nil {
		return guid, 0, err
	}
	value, err := object.Values("uSNChanged").Single()
	if err != nil {
		return guid, 0, err
	}
	text, err := value.Text()
	if err != nil {
		return guid, 0, err
	}
	usn, err := strconv.ParseUint(text, 10, 64)
	return guid, usn, err
}
func readCentralAccessReferences(ctx context.Context, session directorySession, object Object, attribute string, limits CentralAccessReferenceLimits) (result CentralAccessReferencesResult, err error) {
	defer func() {
		result.Error = err
		if err != nil {
			result.Complete = false
		}
	}()
	reader, ok := session.(centralAccessRangedSession)
	if !ok {
		return result, ErrUnsupported
	}
	guid, usn, err := centralAccessVersion(object)
	if err != nil {
		return result, err
	}
	seen := map[string]struct{}{}
	start, remaining := uint64(0), limits.MaxBytes
	for {
		if err := context.Cause(ctx); err != nil {
			return result, err
		}
		if len(result.Ranges) >= limits.MaxRanges || len(result.References) >= limits.MaxReferences {
			return result, ErrCentralAccessReferences
		}
		count := min(1500, limits.MaxReferences-len(result.References))
		property := fmt.Sprintf("%s;range=%d-%d", attribute, start, start+uint64(count)-1)
		attrs, readErr := reader.rangedBaseObject(ctx, objectGUIDTarget(guid), []string{property, "objectGUID", "uSNChanged"})
		result.Ranges = append(result.Ranges, CentralAccessReferenceRange{RequestedProperty: property, Attributes: attrs, Error: readErr})
		for name, values := range attrs {
			if err := context.Cause(ctx); err != nil {
				return result, errors.Join(readErr, err)
			}
			if len(name) > remaining {
				return result, errors.Join(readErr, ErrCentralAccessReferences)
			}
			remaining -= len(name)
			for _, value := range values {
				if err := context.Cause(ctx); err != nil {
					return result, errors.Join(readErr, err)
				}
				if len(value) > remaining {
					return result, errors.Join(readErr, ErrCentralAccessReferences)
				}
				remaining -= len(value)
			}
		}
		values, next, terminal, present, rangeErr := directoryReferenceRange(attrs, attribute, start)
		result.AttributeReturned = result.AttributeReturned || present
		if len(values) > limits.MaxReferences-len(result.References) {
			return result, errors.Join(readErr, rangeErr, ErrCentralAccessReferences)
		}
		for _, value := range values {
			if err := context.Cause(ctx); err != nil {
				return result, errors.Join(readErr, rangeErr, err)
			}
			raw := NewRawValue(value)
			dn, e := raw.Text()
			if e == nil {
				var parsed identityDN
				parsed, e = parseIdentityDN(dn)
				if e == nil {
					key := identityDNKey(parsed)
					if _, exists := seen[key]; exists {
						e = ErrInvalidResult
					}
					seen[key] = struct{}{}
				}
			}
			result.References = append(result.References, CentralAccessReference{DistinguishedName: dn, Raw: raw})
			rangeErr = errors.Join(rangeErr, e)
		}
		actualGUID, actualUSN, versionErr := centralAccessVersion(Object{Attributes: attrs})
		if versionErr == nil && (actualGUID != guid || actualUSN != usn) {
			versionErr = ErrCentralAccessReferences
		}
		if e := errors.Join(readErr, rangeErr, versionErr); e != nil {
			return result, e
		}
		if terminal {
			result.Complete = true
			return result, nil
		}
		start = next
	}
}

type CentralAccessPolicyMembersRequest struct {
	Identity Identity
	Members  []Identity
	Options  ObjectMutationOptions
}
type CentralAccessMemberInput struct {
	Identity    Identity
	Observation IdentityResult
}
type CentralAccessPolicyMembersResult struct {
	Mutation      ObjectMutationResult
	Inputs        []CentralAccessMemberInput
	Before, After CentralAccessReferencesResult
}

func (c *Client) AddCentralAccessPolicyMembers(ctx context.Context, request CentralAccessPolicyMembersRequest) (CentralAccessPolicyMembersResult, error) {
	return c.changeCentralAccessMembers(ctx, request, false)
}
func (c *Client) RemoveCentralAccessPolicyMembers(ctx context.Context, request CentralAccessPolicyMembersRequest) (CentralAccessPolicyMembersResult, error) {
	return c.changeCentralAccessMembers(ctx, request, true)
}
func (c *Client) changeCentralAccessMembers(ctx context.Context, request CentralAccessPolicyMembersRequest, remove bool) (CentralAccessPolicyMembersResult, error) {
	var result CentralAccessPolicyMembersResult
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	if len(request.Members) == 0 || len(request.Members) > CentralAccessPolicyMemberLimit {
		return result, ErrCentralAccessMemberLimit
	}
	for _, identity := range request.Members {
		if err := centralAccessIdentity(identity, ResolveIdentityOptions{}); err != nil {
			return result, err
		}
	}
	ctx, cancel, options, err := c.centralAccessMutationContext(ctx, request.Options)
	if err != nil {
		return result, err
	}
	defer cancel()
	result.Mutation, err = c.objectMutationIdentity(ctx, request.Identity, options, ResolveIdentityOptions{Properties: centralAccessProperties(options.Properties, true)}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		configuration, e := centralAccessConfiguration(root, c.config, options.Partition)
		if e != nil {
			return e
		}
		if e := centralAccessLocation(*observed.Object, configuration, true); e != nil {
			return e
		}
		limits, _ := normalizeCentralAccessLimits(CentralAccessReferenceLimits{})
		result.Before, e = readCentralAccessReferences(ctx, session, *observed.Object, centralMembers, limits)
		if e != nil {
			return e
		}
		if !remove && len(result.Before.References)+len(request.Members) > CentralAccessPolicyMemberLimit {
			return ErrCentralAccessMemberLimit
		}
		values := make([][]byte, 0, len(request.Members))
		seen := map[string]struct{}{}
		for _, identity := range request.Members {
			input, e := resolveIdentitySession(ctx, session, c.config, root, identity, ResolveIdentityOptions{Partition: configuration, Properties: centralAccessProperties(nil, false)})
			result.Inputs = append(result.Inputs, CentralAccessMemberInput{Identity: identity, Observation: input})
			if e != nil {
				return e
			}
			if e := centralAccessLocation(*input.Object, configuration, false); e != nil {
				return e
			}
			parsed, e := parseIdentityDN(input.Object.DistinguishedName)
			if e != nil {
				return e
			}
			key := identityDNKey(parsed)
			if _, exists := seen[key]; exists {
				return ErrCentralAccess
			}
			seen[key] = struct{}{}
			values = append(values, []byte(input.Object.DistinguishedName))
		}
		operation := uint32(0)
		if remove {
			operation = 1
		}
		controls, e := objectWriteControls(root, c.config.Endpoint, options, *mutation.TargetGUID, false)
		if e != nil {
			return e
		}
		if e := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*mutation.TargetGUID), modifications: []ldapAttributeModification{{operation: operation, attribute: centralMembers, values: values}}, controls: controls}, false, mutation); e != nil {
			return e
		}
		if e := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*mutation.TargetGUID), mutation, centralAccessProperties(options.Properties, true), false); e != nil {
			return e
		}
		result.After, e = readCentralAccessReferences(ctx, session, *mutation.After, centralMembers, limits)
		if e != nil {
			return errors.Join(ErrObjectReadback, e)
		}
		if len(result.After.References) > CentralAccessPolicyMemberLimit {
			return ErrCentralAccessMemberLimit
		}
		if !result.After.AttributeReturned {
			return ErrObjectVerification
		}
		actual := map[string]struct{}{}
		for _, ref := range result.After.References {
			if err := context.Cause(ctx); err != nil {
				return err
			}
			parsed, e := parseIdentityDN(ref.DistinguishedName)
			if e != nil {
				return e
			}
			actual[identityDNKey(parsed)] = struct{}{}
		}
		for key := range seen {
			if err := context.Cause(ctx); err != nil {
				return err
			}
			_, present := actual[key]
			if present == remove {
				return ErrObjectVerification
			}
		}
		mutation.Verified = true
		return nil
	})
	return result, err
}

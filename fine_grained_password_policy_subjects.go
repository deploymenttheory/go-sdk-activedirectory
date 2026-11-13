package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type FineGrainedPolicySubjectsOptions struct {
	Partition                        string
	Properties                       []string
	MaxSubjects, MaxRanges, MaxBytes int
}
type FineGrainedPolicySubject struct {
	DistinguishedName string
	Raw               RawValue
	Observation       IdentityResult
	Error             error
}
type FineGrainedPolicySubjectRange struct {
	RequestedProperty string
	Attributes        map[string][][]byte
	Error             error
}

// Complete means all contiguous ranges and subject resolutions completed at
// one observed PSO GUID/USN. It does not prove ACL visibility or a transaction.
// AttributeReturned distinguishes omission from a returned empty attribute.
type FineGrainedPolicySubjectsResult struct {
	Policy                      IdentityResult
	Subjects                    []FineGrainedPolicySubject
	Ranges                      []FineGrainedPolicySubjectRange
	AttributeReturned, Complete bool
	Version                     *ObjectVersion
}
type fineGrainedRangedReader interface {
	rangedBaseObject(context.Context, string, []string) (map[string][][]byte, error)
}

func normalizeFineGrainedSubjectOptions(options FineGrainedPolicySubjectsOptions) (FineGrainedPolicySubjectsOptions, error) {
	if options.MaxSubjects < 0 || options.MaxRanges < 0 || options.MaxBytes < 0 {
		return options, ErrInvalidFineGrainedPolicy
	}
	if options.MaxSubjects == 0 {
		options.MaxSubjects = 100000
	}
	if options.MaxRanges == 0 {
		options.MaxRanges = 1000
	}
	if options.MaxBytes == 0 {
		options.MaxBytes = 64 << 20
	}
	return options, nil
}

func fineGrainedObjectVersion(object Object) (GUID, uint64, error) {
	value, err := object.Values("objectGUID").Single()
	if err != nil {
		return GUID{}, 0, err
	}
	guid, err := value.GUID()
	if err != nil {
		return guid, 0, err
	}
	value, err = object.Values("uSNChanged").Single()
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

// The member-link range contract is reused for the PSO's linked attribute.
// Empty plain+range responses are allowed; gaps, multiple ranges and count
// mismatches remain errors. Raw batches survive every validation/read failure.
func fineGrainedSubjectRange(attributes map[string][][]byte, start uint64) (values [][]byte, next uint64, terminal, present bool, err error) {
	var plain [][]byte
	var rangeName string
	plainFound := false
	for name, data := range attributes {
		lower := strings.ToLower(name)
		if lower == "msds-psoappliesto" {
			if plainFound {
				return nil, 0, false, true, ErrInvalidResult
			}
			plain, plainFound = data, true
		} else if strings.HasPrefix(lower, "msds-psoappliesto;") {
			if rangeName != "" || !strings.HasPrefix(lower, "msds-psoappliesto;range=") {
				return nil, 0, false, true, ErrInvalidResult
			}
			rangeName, values = lower, data
		}
	}
	if rangeName == "" {
		if start != 0 {
			return plain, 0, false, plainFound, ErrIncompleteResult
		}
		return plain, 0, true, plainFound, nil
	}
	if len(plain) != 0 {
		return values, 0, false, true, ErrInvalidResult
	}
	low, high, ok := strings.Cut(strings.TrimPrefix(rangeName, "msds-psoappliesto;range="), "-")
	first, parseErr := strconv.ParseUint(low, 10, 64)
	if !ok || parseErr != nil || first != start {
		return values, 0, false, true, ErrInvalidResult
	}
	if high == "*" {
		return values, 0, true, true, nil
	}
	last, parseErr := strconv.ParseUint(high, 10, 64)
	if parseErr != nil || last < first || last == ^uint64(0) || len(values) == 0 || last-first != uint64(len(values))-1 {
		return values, 0, false, true, ErrInvalidResult
	}
	return values, last + 1, false, true, nil
}

func (c *Client) FineGrainedPasswordPolicySubjects(ctx context.Context, identity Identity, options FineGrainedPolicySubjectsOptions) (FineGrainedPolicySubjectsResult, error) {
	var result FineGrainedPolicySubjectsResult
	options, err := normalizeFineGrainedSubjectOptions(options)
	if err != nil {
		return result, err
	}
	resolve := ResolveIdentityOptions{Partition: options.Partition, Properties: []string{"objectClass", "objectGUID", "uSNChanged"}}
	if err := fineGrainedMutationOptions(identity, ObjectMutationOptions{Partition: options.Partition, Properties: options.Properties}); err != nil {
		return result, err
	}
	err = c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		domain, err := fineGrainedPolicyDomain(root, c.config, options.Partition)
		if err != nil {
			return err
		}
		resolve.Partition = domain
		result.Policy, err = resolveIdentitySession(ctx, c.session, c.config, root, identity, resolve)
		if err != nil {
			return err
		}
		if err := fineGrainedPolicyLocation(*result.Policy.Object, domain); err != nil {
			return err
		}
		return collectFineGrainedSubjects(ctx, c.session, c.config, root, options, &result)
	})
	if err != nil {
		result.Complete = false
	}
	return result, err
}

func collectFineGrainedSubjects(ctx context.Context, session directorySession, config Config, root RootDSE, options FineGrainedPolicySubjectsOptions, result *FineGrainedPolicySubjectsResult) error {
	reader, ok := session.(fineGrainedRangedReader)
	if !ok {
		return ErrUnsupported
	}
	guid, usn, err := fineGrainedObjectVersion(*result.Policy.Object)
	if err != nil {
		return err
	}
	result.Version = &ObjectVersion{Source: config.Endpoint, GUID: guid, USNChanged: usn}
	start, remaining := uint64(0), options.MaxBytes
	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		if len(result.Ranges) >= options.MaxRanges || len(result.Subjects) >= options.MaxSubjects {
			return ErrFineGrainedPolicyLimit
		}
		count := min(1500, options.MaxSubjects-len(result.Subjects))
		property := fmt.Sprintf("msDS-PSOAppliesTo;range=%d-%d", start, start+uint64(count)-1)
		attrs, readErr := reader.rangedBaseObject(ctx, objectGUIDTarget(guid), []string{property, "objectGUID", "uSNChanged"})
		result.Ranges = append(result.Ranges, FineGrainedPolicySubjectRange{RequestedProperty: property, Attributes: attrs, Error: readErr})
		for name, values := range attrs {
			if len(name) > remaining {
				return errors.Join(readErr, ErrFineGrainedPolicyLimit)
			}
			remaining -= len(name)
			for _, value := range values {
				if len(value) > remaining {
					return errors.Join(readErr, ErrFineGrainedPolicyLimit)
				}
				remaining -= len(value)
			}
		}
		values, next, terminal, present, rangeErr := fineGrainedSubjectRange(attrs, start)
		result.AttributeReturned = result.AttributeReturned || present
		if len(values) > options.MaxSubjects-len(result.Subjects) {
			return errors.Join(readErr, rangeErr, ErrFineGrainedPolicyLimit)
		}
		for _, value := range values {
			raw := NewRawValue(value)
			dn, decodeErr := raw.Text()
			result.Subjects = append(result.Subjects, FineGrainedPolicySubject{DistinguishedName: dn, Raw: raw, Error: decodeErr})
			rangeErr = errors.Join(rangeErr, decodeErr)
		}
		actualGUID, actualUSN, versionErr := fineGrainedObjectVersion(Object{Attributes: attrs})
		if versionErr == nil && (actualGUID != guid || actualUSN != usn) {
			versionErr = ErrFineGrainedPolicyChanged
		}
		if err := errors.Join(readErr, rangeErr, versionErr); err != nil {
			return err
		}
		if terminal {
			break
		}
		start = next
	}
	var resolutionErr error
	for i := range result.Subjects {
		subject := &result.Subjects[i]
		if err := context.Cause(ctx); err != nil {
			return errors.Join(resolutionErr, err)
		}
		identity, err := IdentityByDN(subject.DistinguishedName)
		if err == nil {
			subject.Observation, err = resolveIdentitySession(ctx, session, config, root, identity, ResolveIdentityOptions{Partition: result.Policy.Partition, Properties: append(append([]string{}, options.Properties...), "objectGUID", "objectClass", "sAMAccountName", "objectSid", "groupType")})
		}
		subject.Error = err
		resolutionErr = errors.Join(resolutionErr, err)
	}
	result.Complete = resolutionErr == nil
	return resolutionErr
}

type FineGrainedPolicySubjectsRequest struct {
	Identity Identity
	Subjects []Identity
	Options  ObjectMutationOptions
}
type FineGrainedPolicySubjectInput struct {
	Identity    Identity
	Reference   string
	Observation IdentityResult
}
type FineGrainedPolicySubjectsMutationResult struct {
	Mutation ObjectMutationResult
	Subjects []FineGrainedPolicySubjectInput
	After    FineGrainedPolicySubjectsResult
}

func fineGrainedSubjectClass(object Object) error {
	if groupClass(object) == nil {
		group, err := decodeGroup(object)
		if err != nil {
			return err
		}
		if group.Category == nil || group.Scope == nil || *group.Category != GroupSecurity || *group.Scope != GroupGlobal {
			return ErrFineGrainedPolicySubject
		}
		return nil
	}
	if err := accountControlClass(object, DirectoryADDS); err != nil {
		return ErrFineGrainedPolicySubject
	}
	value, err := object.Values("userAccountControl").Single()
	if err != nil {
		return errors.Join(ErrFineGrainedPolicySubject, err)
	}
	flags, err := value.Flags32()
	if err != nil || !flags.Has(0x200) {
		return errors.Join(ErrFineGrainedPolicySubject, err)
	}
	return nil
}

func (c *Client) AddFineGrainedPasswordPolicySubjects(ctx context.Context, request FineGrainedPolicySubjectsRequest) (FineGrainedPolicySubjectsMutationResult, error) {
	return c.changeFineGrainedPolicySubjects(ctx, request, false)
}
func (c *Client) RemoveFineGrainedPasswordPolicySubjects(ctx context.Context, request FineGrainedPolicySubjectsRequest) (FineGrainedPolicySubjectsMutationResult, error) {
	return c.changeFineGrainedPolicySubjects(ctx, request, true)
}

// Resolve every supplied identity before a single strict linked-value Modify.
// GUID references retain identity across renames; duplicates are rejected.
func (c *Client) changeFineGrainedPolicySubjects(ctx context.Context, request FineGrainedPolicySubjectsRequest, remove bool) (FineGrainedPolicySubjectsMutationResult, error) {
	var result FineGrainedPolicySubjectsMutationResult
	if err := fineGrainedMutationOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	if len(request.Subjects) == 0 || len(request.Subjects) > 1000 {
		return result, ErrFineGrainedPolicyLimit
	}
	for _, identity := range request.Subjects {
		if err := validateIdentityOperation(identity, accountControlIdentity(identity, request.Options.Partition, nil)); err != nil {
			return result, err
		}
		result.Subjects = append(result.Subjects, FineGrainedPolicySubjectInput{Identity: identity})
	}
	var err error
	result.Mutation, err = c.mutateFineGrainedPolicy(ctx, request.Identity, request.Options, func(ctx context.Context, session ldapWriteSession, root RootDSE, _ IdentityResult, mutation *ObjectMutationResult) error {
		controls, err := objectWriteControls(root, c.config.Endpoint, request.Options, *mutation.TargetGUID, false)
		if err != nil {
			return err
		}
		seen := make(map[GUID]bool)
		values := make([][]byte, 0, len(request.Subjects))
		for i, identity := range request.Subjects {
			resolved, err := resolveIdentitySession(ctx, session, c.config, root, identity, accountControlIdentity(identity, mutation.Partition, []string{"groupType"}))
			result.Subjects[i].Observation = resolved
			if err != nil {
				return err
			}
			if err := fineGrainedSubjectClass(*resolved.Object); err != nil {
				return err
			}
			value, err := resolved.Object.Values("objectGUID").Single()
			if err != nil {
				return err
			}
			guid, err := value.GUID()
			if err != nil {
				return err
			}
			if seen[guid] {
				return ErrInvalidFineGrainedPolicy
			}
			seen[guid] = true
			reference := objectGUIDTarget(guid)
			result.Subjects[i].Reference = reference
			values = append(values, []byte(reference))
		}
		operation := uint32(0)
		if remove {
			operation = 1
		}
		write := ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*mutation.TargetGUID), modifications: []ldapAttributeModification{{operation: operation, attribute: "msDS-PSOAppliesTo", values: values}}, controls: controls}
		if err := submitObjectWrite(ctx, session, write, false, mutation); err != nil {
			return err
		}
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*mutation.TargetGUID), mutation, fineGrainedPolicyProperties(append(append([]string{}, request.Options.Properties...), "uSNChanged")), false); err != nil {
			return err
		}
		result.After.Policy = IdentityResult{Object: mutation.After, Partition: mutation.Partition, Complete: true}
		limits, _ := normalizeFineGrainedSubjectOptions(FineGrainedPolicySubjectsOptions{Partition: mutation.Partition})
		if err := collectFineGrainedSubjects(ctx, session, c.config, root, limits, &result.After); err != nil {
			return errors.Join(ErrObjectReadback, err)
		}
		if !result.After.AttributeReturned {
			return ErrObjectVerification
		}
		found := make(map[GUID]bool)
		for _, subject := range result.After.Subjects {
			value, e := subject.Observation.Object.Values("objectGUID").Single()
			if e != nil {
				return e
			}
			guid, e := value.GUID()
			if e != nil {
				return e
			}
			found[guid] = true
		}
		for guid := range seen {
			if found[guid] == remove {
				return ErrObjectVerification
			}
		}
		mutation.Verified = true
		return nil
	})
	return result, err
}

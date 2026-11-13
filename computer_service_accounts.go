package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
)

var ErrServiceAccountAssociationLimit = errors.New("computer service account association limit reached")

const serviceAccountMaxLinks = 100000
const serviceAccountMaxRanges = 1000
const serviceAccountMaxBytes = 64 << 20

// These operations edit directory links only. They do not install an account,
// reset its password, or grant a computer permission to retrieve a gMSA secret.
type ComputerServiceAccountRequest struct {
	Computer Identity
	Accounts []Identity
	// Strict by default. Permissive asks the server to ignore existing adds or
	// absent deletes using its advertised critical permissive-modify control.
	Permissive bool
	Options    ObjectMutationOptions
}
type ComputerServiceAccountMutationResult struct {
	Mutation ObjectMutationResult
	Accounts []IdentityResult
	Links    *ComputerServiceAccountsResult
}
type ComputerServiceAccountsOptions struct {
	Partition                      string
	MaxValues, MaxRanges, MaxBytes int
}
type ComputerServiceAccountRange struct {
	Property   string
	Attributes map[string][][]byte
	Error      error
}
type ComputerServiceAccountLink struct {
	DistinguishedName string
	Account           *ServiceAccount
	Observation       IdentityResult
	Error             error
}

// Complete describes enumeration and resolution, not visibility through ACLs.
// AttributeReturned=false cannot establish that no associations exist.
type ComputerServiceAccountsResult struct {
	Computer                    IdentityResult
	Links                       []ComputerServiceAccountLink
	Ranges                      []ComputerServiceAccountRange
	Version                     *ObjectVersion
	AttributeReturned, Complete bool
}

func (c *Client) AddComputerServiceAccounts(ctx context.Context, request ComputerServiceAccountRequest) (ComputerServiceAccountMutationResult, error) {
	return c.changeComputerServiceAccounts(ctx, request, true)
}
func (c *Client) RemoveComputerServiceAccounts(ctx context.Context, request ComputerServiceAccountRequest) (ComputerServiceAccountMutationResult, error) {
	return c.changeComputerServiceAccounts(ctx, request, false)
}
func (c *Client) changeComputerServiceAccounts(ctx context.Context, request ComputerServiceAccountRequest, add bool) (result ComputerServiceAccountMutationResult, err error) {
	if len(request.Accounts) == 0 || len(request.Accounts) > serviceAccountMaxLinks {
		return result, ErrInvalidServiceAccount
	}
	if err = validateServiceAccountProjection(request.Options.Properties); err != nil {
		return
	}
	result.Mutation, err = c.objectMutationIdentity(ctx, request.Computer, request.Options, computerIdentityOptions(request.Computer, request.Options.Partition, nil), func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		if e := root.Capabilities().RequireADDS("ComputerServiceAccounts"); e != nil {
			return e
		}
		if e := computerClass(*observed.Object); e != nil {
			return e
		}
		if root.Capabilities().Has("1.2.840.113556.1.4.1920") {
			return ErrObjectWriteTarget
		}
		controls, e := objectWriteControls(root, c.config.Endpoint, request.Options, *mutation.TargetGUID, false)
		if e != nil {
			return e
		}
		if request.Permissive {
			const oid = "1.2.840.113556.1.4.1413"
			if !slices.Contains(root.SupportedControls, oid) {
				return ErrObjectControlUnsupported
			}
			controls = append(controls, ldapWriteControl{oid: oid, critical: true})
		}
		values := []RawValue{}
		seen := map[string]bool{}
		for _, identity := range request.Accounts {
			if e := context.Cause(ctx); e != nil {
				return e
			}
			observation, e := resolveIdentitySession(ctx, session, c.config, root, identity, serviceAccountIdentityOptions(identity, mutation.Partition, nil))
			result.Accounts = append(result.Accounts, observation)
			if e != nil {
				return e
			}
			if _, e = serviceAccountClass(*observation.Object); e != nil {
				return e
			}
			dn := observation.Object.DistinguishedName
			value, e := observation.Object.Values("objectGUID").Single()
			if e != nil {
				return e
			}
			guid, e := value.GUID()
			if e != nil {
				return e
			}
			key := guid.String()
			if seen[key] {
				return ErrInvalidServiceAccount
			}
			seen[key] = true
			values = append(values, NewRawValue([]byte(dn)))
		}
		kind := AttributeAddValues
		if !add {
			kind = AttributeRemoveValues
		}
		mods, e := objectChanges([]AttributeChange{{Attribute: "msDS-HostServiceAccount", Kind: kind, Values: values}})
		if e != nil {
			return e
		}
		if e = submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*mutation.TargetGUID), modifications: mods, controls: controls}, false, mutation); e != nil {
			return e
		}
		if e = observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*mutation.TargetGUID), mutation, append(slices.Clone(request.Options.Properties), "objectGUID", "uSNChanged", "objectClass"), false); e != nil {
			return e
		}
		guid, usn, e := serviceAccountLinkVersion(*mutation.After)
		if e != nil {
			return errors.Join(ErrObjectReadback, e)
		}
		links := ComputerServiceAccountsResult{Version: &ObjectVersion{Source: c.config.Endpoint, GUID: guid, USNChanged: usn}}
		result.Links = &links
		reader, ok := session.(serviceAccountRangeReader)
		if !ok {
			return errors.Join(ErrObjectReadback, ErrUnsupported)
		}
		if e = collectComputerServiceAccountLinks(ctx, reader, ComputerServiceAccountsOptions{MaxValues: serviceAccountMaxLinks, MaxRanges: serviceAccountMaxRanges, MaxBytes: serviceAccountMaxBytes}, &links); e != nil {
			return errors.Join(ErrObjectReadback, e)
		}
		if !links.AttributeReturned {
			return ErrObjectVerification
		}
		present := map[string]bool{}
		for _, link := range links.Links {
			if e := context.Cause(ctx); e != nil {
				return errors.Join(ErrObjectReadback, e)
			}
			dn, e := parseIdentityDN(link.DistinguishedName)
			if e != nil {
				return errors.Join(ErrObjectVerification, e)
			}
			present[identityDNKey(dn)] = true
		}
		for _, value := range values {
			if e := context.Cause(ctx); e != nil {
				return errors.Join(ErrObjectReadback, e)
			}
			text, e := value.Text()
			if e != nil {
				return e
			}
			dn, e := parseIdentityDN(text)
			if e != nil {
				return e
			}
			if present[identityDNKey(dn)] != add {
				return ErrObjectVerification
			}
		}
		mutation.Verified = true
		return nil
	})
	return
}

type serviceAccountRangeReader interface {
	rangedBaseObject(context.Context, string, []string) (map[string][][]byte, error)
}

func (c *Client) ComputerServiceAccounts(ctx context.Context, identity Identity, options ComputerServiceAccountsOptions) (result ComputerServiceAccountsResult, err error) {
	if options.MaxValues < 0 || options.MaxRanges < 0 || options.MaxBytes < 0 || options.MaxValues > serviceAccountMaxLinks || options.MaxRanges > serviceAccountMaxRanges || options.MaxBytes > serviceAccountMaxBytes {
		return result, ErrInvalidServiceAccount
	}
	if options.MaxValues == 0 {
		options.MaxValues = serviceAccountMaxLinks
	}
	if options.MaxRanges == 0 {
		options.MaxRanges = serviceAccountMaxRanges
	}
	if options.MaxBytes == 0 {
		options.MaxBytes = serviceAccountMaxBytes
	}
	resolve := computerIdentityOptions(identity, options.Partition, []string{"uSNChanged"})
	if err = validateIdentityOperation(identity, resolve); err != nil {
		return
	}
	err = c.read(ctx, func(ctx context.Context) error {
		root, e := readIdentityRoot(ctx, c.session)
		if e != nil {
			return e
		}
		if e = root.Capabilities().RequireADDS("ComputerServiceAccounts"); e != nil {
			return e
		}
		if c.config.Endpoint.Port == 3268 || c.config.Endpoint.Port == 3269 {
			return ErrObjectWriteTarget
		}
		result.Computer, e = resolveIdentitySession(ctx, c.session, c.config, root, identity, resolve)
		if e != nil {
			return e
		}
		if e = computerClass(*result.Computer.Object); e != nil {
			return e
		}
		guid, usn, e := serviceAccountLinkVersion(*result.Computer.Object)
		if e != nil {
			return e
		}
		result.Version = &ObjectVersion{Source: c.config.Endpoint, GUID: guid, USNChanged: usn}
		reader, ok := c.session.(serviceAccountRangeReader)
		if !ok {
			return ErrUnsupported
		}
		if e = collectComputerServiceAccountLinks(ctx, reader, options, &result); e != nil {
			return e
		}
		for i := range result.Links {
			if cause := context.Cause(ctx); cause != nil {
				return errors.Join(e, cause)
			}
			link := &result.Links[i]
			id, x := IdentityByDN(link.DistinguishedName)
			if x == nil {
				link.Observation, x = resolveIdentitySession(ctx, c.session, c.config, root, id, serviceAccountIdentityOptions(id, result.Computer.Partition, nil))
				if link.Observation.Object != nil {
					account, decodeErr := decodeServiceAccount(*link.Observation.Object)
					link.Account = &account
					x = errors.Join(x, decodeErr)
				}
			}
			link.Error = x
			e = errors.Join(e, x)
		}
		return e
	})
	if err != nil {
		result.Complete = false
	}
	return
}
func serviceAccountLinkVersion(object Object) (GUID, uint64, error) {
	v, err := object.Values("objectGUID").Single()
	if err != nil {
		return GUID{}, 0, err
	}
	guid, err := v.GUID()
	if err != nil {
		return GUID{}, 0, err
	}
	v, err = object.Values("uSNChanged").Single()
	if err != nil {
		return guid, 0, err
	}
	text, err := v.Text()
	if err != nil {
		return guid, 0, err
	}
	usn, err := strconv.ParseUint(text, 10, 64)
	return guid, usn, err
}
func collectComputerServiceAccountLinks(ctx context.Context, reader serviceAccountRangeReader, options ComputerServiceAccountsOptions, result *ComputerServiceAccountsResult) error {
	start, remaining := uint64(0), options.MaxBytes
	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		if len(result.Ranges) >= options.MaxRanges || len(result.Links) >= options.MaxValues {
			return ErrServiceAccountAssociationLimit
		}
		count := min(1500, options.MaxValues-len(result.Links))
		property := fmt.Sprintf("msDS-HostServiceAccount;range=%d-%d", start, start+uint64(count)-1)
		attrs, readErr := reader.rangedBaseObject(ctx, objectGUIDTarget(result.Version.GUID), []string{property, "objectGUID", "uSNChanged"})
		result.Ranges = append(result.Ranges, ComputerServiceAccountRange{Property: property, Attributes: attrs, Error: readErr})
		for name, values := range attrs {
			if cause := context.Cause(ctx); cause != nil {
				return errors.Join(readErr, cause)
			}
			if len(name) > remaining {
				return errors.Join(readErr, ErrServiceAccountAssociationLimit)
			}
			remaining -= len(name)
			for _, value := range values {
				if cause := context.Cause(ctx); cause != nil {
					return errors.Join(readErr, cause)
				}
				if len(value) > remaining {
					return errors.Join(readErr, ErrServiceAccountAssociationLimit)
				}
				remaining -= len(value)
			}
		}
		values, next, terminal, present, err := directoryReferenceRange(attrs, "msDS-HostServiceAccount", start)
		result.AttributeReturned = result.AttributeReturned || present
		if len(values) > options.MaxValues-len(result.Links) {
			return errors.Join(readErr, err, ErrServiceAccountAssociationLimit)
		}
		for _, value := range values {
			if cause := context.Cause(ctx); cause != nil {
				return errors.Join(readErr, err, cause)
			}
			text, e := NewRawValue(value).Text()
			if e == nil {
				_, e = IdentityByDN(text)
			}
			if e != nil {
				err = errors.Join(err, e)
				continue
			}
			result.Links = append(result.Links, ComputerServiceAccountLink{DistinguishedName: text})
		}
		guid, usn, e := serviceAccountLinkVersion(Object{Attributes: attrs})
		if e == nil && (guid != result.Version.GUID || usn != result.Version.USNChanged) {
			e = ErrObjectConcurrency
		}
		if e = errors.Join(readErr, err, e); e != nil {
			return e
		}
		if terminal {
			result.Complete = true
			return nil
		}
		start = next
	}
}

package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strings"
)

var (
	ErrNotComputer                = errors.New("directory object is not a computer account")
	ErrInvalidComputer            = errors.New("invalid computer request")
	ErrComputerCreationIncomplete = errors.New("computer creation did not complete all requested stages; inspect stage results before further writes")
)

// ComputerProperties changes only non-nil fields. Clear and multivalue changes
// use AttributeChange. KerberosEncryptionTypes selects the low five AD cmdlet
// encryption bits; CompoundIdentitySupported owns bit 0x40 independently.
type ComputerProperties struct {
	SAMAccountName, DNSHostName, UserPrincipalName, DisplayName, Description                   *string
	Location, ManagedByDN, HomePage                                                            *string
	OperatingSystem, OperatingSystemVersion, OperatingSystemServicePack, OperatingSystemHotfix *string
	AccountExpires                                                                             *FileTime
	KerberosEncryptionTypes                                                                    *Flags32
	CompoundIdentitySupported                                                                  *bool
}

// Computer preserves raw and ranged values. AccountControl separates stored
// flags from server-computed state; nil properties were not returned.
type Computer struct {
	ComputerProperties
	DistinguishedName                                        string
	Name                                                     *string
	GUID                                                     *GUID
	SID                                                      *SID
	SupportedEncryptionTypes                                 *Flags32
	LastLogonDate                                            *FileTime
	AccountControl                                           AccountControlState
	ServicePrincipalNames, Certificates, AllowedToDelegateTo AttributeValues
	Raw                                                      Object
}

type ComputerResult struct {
	Computer    *Computer
	Observation IdentityResult
}
type ComputersResult struct {
	Computers   []Computer
	Observation SearchResult
}
type ComputerMutationResult struct {
	Computer *Computer
	Mutation ObjectMutationResult
}

// CreateComputerRequest creates a disabled workstation-trust account under an
// explicit parent or the configured Computers container when Parent is omitted.
// Omitted SAMAccountName derives from Name. Typed SAM names
// receive a trailing $ when absent. This never joins or configures a machine.
// InitialPassword follows PasswordResetRequest's caller-owned UTF-8 rules.
type CreateComputerRequest struct {
	Parent          Identity
	Name            string
	Properties      ComputerProperties
	Control         AccountControlPatch
	InitialPassword []byte `json:"-"`
	Attributes      map[string][]RawValue
	Options         ObjectMutationOptions
}

func (CreateComputerRequest) String() string               { return "CreateComputerRequest{redacted}" }
func (CreateComputerRequest) GoString() string             { return "CreateComputerRequest{redacted}" }
func (CreateComputerRequest) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (CreateComputerRequest) MarshalText() ([]byte, error) {
	return []byte("CreateComputerRequest{redacted}"), nil
}

// ComputerCreationResult retains independent nontransactional stage outcomes.
// Nil stage pointers mean not entered. No accepted creation is rolled back.
type ComputerCreationResult struct {
	Creation    ObjectMutationResult
	Password    *PasswordResult
	Enable      *ObjectMutationResult
	Computer    *Computer
	Observation *ComputerResult
	Complete    bool
}
type UpdateComputerRequest struct {
	Identity   Identity
	Properties ComputerProperties
	Control    AccountControlPatch
	Changes    []AttributeChange
	Options    ObjectMutationOptions
}

// Recursive must be explicit. A submitted tree delete may partially succeed
// even when rejected; the SDK never repeats it to finish deleting descendants.
type DeleteComputerRequest struct {
	Identity  Identity
	Recursive bool
	Options   ObjectMutationOptions
}

func computerProperties(extra []string) []string {
	return append(accountControlProperties(extra), "objectSid", "name", "sAMAccountName", "dNSHostName", "userPrincipalName", "displayName", "description", "location", "managedBy", "wWWHomePage", "operatingSystem", "operatingSystemVersion", "operatingSystemServicePack", "operatingSystemHotfix", "accountExpires", "lastLogonTimestamp", "msDS-SupportedEncryptionTypes", "servicePrincipalName", "userCertificate", "msDS-AllowedToDelegateTo")
}
func computerIdentityOptions(identity Identity, partition string, properties []string) ResolveIdentityOptions {
	options := accountControlIdentity(identity, partition, properties)
	options.Properties = computerProperties(properties)
	return options
}
func computerClass(object Object) error {
	values, state := object.Attribute("objectClass")
	if state != AttributePresent {
		return errors.Join(ErrNotComputer, ErrAttributeUnavailable)
	}
	found := false
	for _, value := range values {
		name, err := NewRawValue(value).Text()
		if err != nil {
			return errors.Join(ErrNotComputer, err)
		}
		switch strings.ToLower(name) {
		case "computer":
			found = true
		case "msds-managedserviceaccount", "msds-groupmanagedserviceaccount", "msds-delegatedmanagedserviceaccount":
			return ErrNotComputer
		}
	}
	if !found {
		return ErrNotComputer
	}
	return nil
}
func computerClassFilter() Filter {
	return FilterAnd(FilterEqual("objectClass", FilterText("computer")), FilterNot(FilterEqual("objectClass", FilterText("msDS-ManagedServiceAccount"))), FilterNot(FilterEqual("objectClass", FilterText("msDS-GroupManagedServiceAccount"))), FilterNot(FilterEqual("objectClass", FilterText("msDS-DelegatedManagedServiceAccount"))))
}
func decodeComputer(object Object, kind DirectoryType) (Computer, error) {
	computer := Computer{DistinguishedName: object.DistinguishedName, Raw: object, ServicePrincipalNames: object.Values("servicePrincipalName"), Certificates: object.Values("userCertificate"), AllowedToDelegateTo: object.Values("msDS-AllowedToDelegateTo")}
	if err := computerClass(object); err != nil {
		return computer, err
	}
	decoder := rootDSEDecoder{attributes: object.Attributes}
	computer.Name = decoder.text("name")
	for _, field := range computerTextFields(&computer.ComputerProperties) {
		*field.value = decoder.text(field.attribute)
	}
	computer.AccountExpires = decodeScalar(&decoder, "accountExpires", ParseFileTime)
	computer.LastLogonDate = decodeScalar(&decoder, "lastLogonTimestamp", ParseFileTime)
	for _, attribute := range []string{"objectGUID", "objectSid", "msDS-SupportedEncryptionTypes"} {
		values := object.Values(attribute)
		if values.State == AttributeAbsent || values.State == AttributeUnloaded {
			continue
		}
		value, err := values.Single()
		if err != nil {
			decoder.errors = append(decoder.errors, err)
			continue
		}
		switch attribute {
		case "objectGUID":
			v, e := value.GUID()
			err = e
			if e == nil {
				computer.GUID = &v
			}
		case "objectSid":
			v, e := value.SID()
			err = e
			if e == nil {
				computer.SID = &v
			}
		default:
			v, e := value.Flags32()
			err = e
			if e == nil {
				computer.SupportedEncryptionTypes = &v
				encryption, compound := v&computerEncryptionMask, v.Has(0x40)
				computer.KerberosEncryptionTypes = &encryption
				computer.CompoundIdentitySupported = &compound
			}
		}
		decoder.errors = append(decoder.errors, err)
	}
	// Extended LDS computer schemas need not inherit a bindable account class.
	// Their ordinary attributes remain readable without inventing account flags.
	computer.AccountControl = AccountControlState{DistinguishedName: object.DistinguishedName, Directory: kind, Raw: object}
	if kind == DirectoryADDS || accountControlClass(object, kind) == nil {
		control, err := decodeAccountControl(object, kind)
		computer.AccountControl = control
		decoder.errors = append(decoder.errors, err)
	}
	return computer, errors.Join(decoder.errors...)
}

func (c *Client) Computer(ctx context.Context, identity Identity, options ResolveIdentityOptions) (ComputerResult, error) {
	var result ComputerResult
	if options.Target > IdentityTargetAccount {
		return result, ErrInvalidIdentity
	}
	options = computerIdentityOptions(identity, options.Partition, options.Properties)
	if err := validateIdentityOperation(identity, options); err != nil {
		return result, err
	}
	err := c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		result.Observation, err = resolveIdentitySession(ctx, c.session, c.config, root, identity, options)
		if result.Observation.Object != nil {
			computer, decodeErr := decodeComputer(*result.Observation.Object, root.Capabilities().Type)
			result.Computer = &computer
			err = errors.Join(err, decodeErr)
		}
		return err
	})
	return result, err
}

func (c *Client) Computers(ctx context.Context, options SearchOptions) (ComputersResult, error) {
	var result ComputersResult
	if err := options.Validate(); err != nil {
		return result, err
	}
	options.Properties = computerProperties(options.Properties)
	class := computerClassFilter()
	if !options.TypedFilter.unset() {
		options.TypedFilter = FilterAnd(class, options.TypedFilter)
	} else if options.Filter != "" {
		encoded, _ := class.LDAP()
		options.Filter = "(&" + encoded + options.Filter + ")"
	} else {
		options.TypedFilter = class
	}
	err := c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		if root.Capabilities().Type == DirectoryUnknown {
			return root.Capabilities().RequireADDS("Computers")
		}
		if options.Base == "" {
			options.Base = c.config.Partition
			if options.Base == "" && root.DefaultNamingContext != nil {
				options.Base = *root.DefaultNamingContext
			}
			if options.Base == "" {
				return ErrNoDefaultPartition
			}
		}
		identity, err := IdentityByDN(options.Base)
		if err != nil {
			return err
		}
		if _, _, err := identityPartition(identity, c.config.Partition, root); err != nil {
			return err
		}
		result.Observation, err = searchIdentitySession(ctx, c.session, options)
		for _, object := range result.Observation.Objects {
			computer, decodeErr := decodeComputer(object, root.Capabilities().Type)
			result.Computers = append(result.Computers, computer)
			err = errors.Join(err, decodeErr)
		}
		return err
	})
	return result, err
}

func computerMutationResult(mutation ObjectMutationResult, err error) (ComputerMutationResult, error) {
	result := ComputerMutationResult{Mutation: mutation}
	if mutation.After != nil {
		computer, decodeErr := decodeComputer(*mutation.After, DirectoryADDS)
		result.Computer = &computer
		err = errors.Join(err, decodeErr)
	}
	return result, err
}
func (c *Client) UpdateComputer(ctx context.Context, request UpdateComputerRequest) (ComputerMutationResult, error) {
	if err := validateIdentityOperation(request.Identity, computerIdentityOptions(request.Identity, request.Options.Partition, request.Options.Properties)); err != nil {
		return ComputerMutationResult{}, err
	}
	if err := validateAccountControlPatch(request.Control); err != nil {
		return ComputerMutationResult{}, err
	}
	changes, err := computerAttributeChanges(request.Properties, request.Changes)
	if err != nil {
		return ComputerMutationResult{}, err
	}
	var mods []ldapAttributeModification
	if len(changes) > 0 {
		mods, err = objectChanges(changes)
		if err != nil {
			return ComputerMutationResult{}, err
		}
	} else if accountControlPatchEmpty(request.Control) && !computerHasEncryption(request.Properties) {
		return ComputerMutationResult{}, ErrInvalidComputer
	}
	request.Options.Properties = computerProperties(request.Options.Properties)
	mutation, err := c.objectMutationIdentity(ctx, request.Identity, request.Options, computerIdentityOptions(request.Identity, request.Options.Partition, request.Options.Properties), func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, result *ObjectMutationResult) error {
		if err := root.Capabilities().RequireADDS("UpdateComputer"); err != nil {
			return err
		}
		if err := computerClass(*observed.Object); err != nil {
			return err
		}
		writes, verification := slices.Clone(mods), slices.Clone(mods)
		if !accountControlPatchEmpty(request.Control) {
			more, verify, err := accountControlChanges(*observed.Object, DirectoryADDS, request.Control)
			if err != nil {
				return err
			}
			writes = append(writes, more...)
			verification = append(verification, verify...)
		}
		more, verify, err := computerEncryptionChanges(*observed.Object, request.Properties)
		if err != nil {
			return err
		}
		writes = append(writes, more...)
		verification = append(verification, verify...)
		if len(writes) == 0 {
			if request.Options.ExpectedVersion != nil {
				return ErrObjectControlUnsupported
			}
			result.After, result.ReadbackComplete = observed.Object, observed.Complete
			return verifyObjectWrite(result, verification, "")
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, request.Options, *result.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*result.TargetGUID), modifications: writes, controls: controls}, false, result); err != nil {
			return err
		}
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*result.TargetGUID), result, objectWriteProperties(request.Options, writes), false); err != nil {
			return err
		}
		if request.Control.ChangePasswordAtLogon != nil && !*request.Control.ChangePasswordAtLogon {
			value, err := result.After.Values("pwdLastSet").Single()
			if err != nil {
				return errors.Join(ErrObjectVerification, err)
			}
			ticks, err := value.Int64()
			if err != nil || ticks <= 0 {
				return errors.Join(ErrObjectVerification, err)
			}
		}
		return verifyObjectWrite(result, verification, "")
	})
	return computerMutationResult(mutation, err)
}

func (c *Client) DeleteComputer(ctx context.Context, request DeleteComputerRequest) (ComputerMutationResult, error) {
	if err := validateIdentityOperation(request.Identity, computerIdentityOptions(request.Identity, request.Options.Partition, request.Options.Properties)); err != nil {
		return ComputerMutationResult{}, err
	}
	mutation, err := c.objectMutationIdentity(ctx, request.Identity, request.Options, computerIdentityOptions(request.Identity, request.Options.Partition, nil), func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, result *ObjectMutationResult) error {
		if err := root.Capabilities().RequireADDS("DeleteComputer"); err != nil {
			return err
		}
		if err := computerClass(*observed.Object); err != nil {
			return err
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, request.Options, *result.TargetGUID, request.Recursive)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteDelete, dn: objectGUIDTarget(*result.TargetGUID), controls: controls}, request.Recursive, result); err != nil {
			return err
		}
		return observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*result.TargetGUID), result, []string{"objectGUID"}, true)
	})
	return computerMutationResult(mutation, err)
}

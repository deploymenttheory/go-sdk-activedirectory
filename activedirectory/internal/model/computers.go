package model

import (
	"errors"
	"strings"
)

var (
	ErrNotComputer                = errors.New("directory object is not a computer account")
	ErrInvalidComputer            = errors.New("invalid computer request")
	ErrComputerCreationIncomplete = errors.New(
		"computer creation did not complete all requested stages; inspect stage results before further writes",
	)
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

func (CreateComputerRequest) String() string { return "CreateComputerRequest{redacted}" }

func (CreateComputerRequest) GoString() string { return "CreateComputerRequest{redacted}" }

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

func InternalComputerProperties(extra []string) []string {
	return append(
		InternalAccountControlProperties(extra),
		"objectSid",
		"name",
		"sAMAccountName",
		"dNSHostName",
		"userPrincipalName",
		"displayName",
		"description",
		"location",
		"managedBy",
		"wWWHomePage",
		"operatingSystem",
		"operatingSystemVersion",
		"operatingSystemServicePack",
		"operatingSystemHotfix",
		"accountExpires",
		"lastLogonTimestamp",
		"msDS-SupportedEncryptionTypes",
		"servicePrincipalName",
		"userCertificate",
		"msDS-AllowedToDelegateTo",
	)
}

func InternalComputerIdentityOptions(
	identity Identity,
	partition string,
	properties []string,
) ResolveIdentityOptions {
	options := InternalAccountControlIdentity(identity, partition, properties)
	options.Properties = InternalComputerProperties(properties)
	return options
}

func InternalComputerClass(object Object) error {
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
		case "msds-managedserviceaccount",
			"msds-groupmanagedserviceaccount",
			"msds-delegatedmanagedserviceaccount":
			return ErrNotComputer
		}
	}
	if !found {
		return ErrNotComputer
	}
	return nil
}

func InternalComputerClassFilter() Filter {
	return FilterAnd(
		FilterEqual("objectClass", FilterText("computer")),
		FilterNot(FilterEqual("objectClass", FilterText("msDS-ManagedServiceAccount"))),
		FilterNot(FilterEqual("objectClass", FilterText("msDS-GroupManagedServiceAccount"))),
		FilterNot(FilterEqual("objectClass", FilterText("msDS-DelegatedManagedServiceAccount"))),
	)
}

func InternalDecodeComputer(object Object, kind DirectoryType) (Computer, error) {
	computer := Computer{
		DistinguishedName:     object.DistinguishedName,
		Raw:                   object,
		ServicePrincipalNames: object.Values("servicePrincipalName"),
		Certificates:          object.Values("userCertificate"),
		AllowedToDelegateTo:   object.Values("msDS-AllowedToDelegateTo"),
	}
	if err := InternalComputerClass(object); err != nil {
		return computer, err
	}
	decoder := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	computer.Name = decoder.InternalText("name")
	for _, field := range InternalComputerTextFields(&computer.ComputerProperties) {
		*field.InternalValue = decoder.InternalText(field.InternalAttribute)
	}
	computer.AccountExpires = InternalDecodeScalar(&decoder, "accountExpires", ParseFileTime)
	computer.LastLogonDate = InternalDecodeScalar(&decoder, "lastLogonTimestamp", ParseFileTime)
	for _, attribute := range []string{"objectGUID", "objectSid", "msDS-SupportedEncryptionTypes"} {
		values := object.Values(attribute)
		if values.State == AttributeAbsent || values.State == AttributeUnloaded {
			continue
		}
		value, err := values.Single()
		if err != nil {
			decoder.InternalErrors = append(decoder.InternalErrors, err)
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
				encryption, compound := v&InternalComputerEncryptionMask, v.Has(0x40)
				computer.KerberosEncryptionTypes = &encryption
				computer.CompoundIdentitySupported = &compound
			}
		}
		decoder.InternalErrors = append(decoder.InternalErrors, err)
	}
	// Extended LDS computer schemas need not inherit a bindable account class.
	// Their ordinary attributes remain readable without inventing account flags.
	computer.AccountControl = AccountControlState{
		DistinguishedName: object.DistinguishedName,
		Directory:         kind,
		Raw:               object,
	}
	if kind == DirectoryADDS || InternalAccountControlClass(object, kind) == nil {
		control, err := InternalDecodeAccountControl(object, kind)
		computer.AccountControl = control
		decoder.InternalErrors = append(decoder.InternalErrors, err)
	}
	return computer, errors.Join(decoder.InternalErrors...)
}

func InternalComputerMutationResult(
	mutation ObjectMutationResult,
	err error,
) (ComputerMutationResult, error) {
	result := ComputerMutationResult{Mutation: mutation}
	if mutation.After != nil {
		computer, decodeErr := InternalDecodeComputer(*mutation.After, DirectoryADDS)
		result.Computer = &computer
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

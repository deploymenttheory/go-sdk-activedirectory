package ldap

import (
	"errors"
	"strings"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func ldapWireField(packet *ber.Packet, class ber.Class, kind ber.Type, tag ber.Tag) bool {
	return packet != nil && packet.ClassType == class && packet.TagType == kind && packet.Tag == tag
}

func ldapWireText(packet *ber.Packet) (string, error) {
	if !ldapWireField(packet, ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString) {
		return "", malformedf("invalid LDAPString field")
	}
	value, err := packetString(packet)
	if err != nil || !utf8.ValidString(value) {
		return "", malformedf("invalid UTF-8 LDAPString field")
	}
	return value, nil
}

func ldapWireOID(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				return false
			}
		}
	}
	return true
}

func validateLDAPURIs(packet *ber.Packet) error {
	if len(packet.Children) == 0 {
		return malformedf("empty LDAP referral")
	}
	for _, uri := range packet.Children {
		value, err := ldapWireText(uri)
		if err != nil || value == "" {
			return malformedf("invalid LDAP referral URI")
		}
	}
	return nil
}

func validateLDAPResultTail(operation *ber.Packet) error {
	position := 3
	if len(operation.Children) > position && ldapWireField(operation.Children[position], ber.ClassContext, ber.TypeConstructed, 3) {
		if err := validateLDAPURIs(operation.Children[position]); err != nil {
			return err
		}
		position++
	}
	switch operation.Tag {
	case ApplicationBindResponse:
		if len(operation.Children) > position && ldapWireField(operation.Children[position], ber.ClassContext, ber.TypePrimitive, 7) {
			position++ // serverSaslCreds is arbitrary binary data, including empty.
		}
	case ApplicationExtendedResponse:
		if len(operation.Children) > position && ldapWireField(operation.Children[position], ber.ClassContext, ber.TypePrimitive, 10) {
			name, err := packetData(operation.Children[position])
			if err != nil || !ldapWireOID(string(name)) {
				return malformedf("invalid extended response OID")
			}
			position++
		}
		if len(operation.Children) > position && ldapWireField(operation.Children[position], ber.ClassContext, ber.TypePrimitive, 11) {
			position++ // responseValue remains opaque binary data.
		}
	}
	if len(operation.Children) != position {
		return malformedf("unexpected fields after LDAPResult")
	}
	return nil
}

func validateLDAPSearchEntry(operation *ber.Packet) error {
	children, err := packetChildCount(operation, 2, 2, "SearchResultEntry")
	if err != nil {
		return err
	}
	if _, err := ldapWireText(children[0]); err != nil {
		return err
	}
	if !ldapWireField(children[1], ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) {
		return malformedf("invalid partial attribute list")
	}
	for _, attribute := range children[1].Children {
		if !ldapWireField(attribute, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) {
			return malformedf("invalid partial attribute")
		}
		fields, err := packetChildCount(attribute, 2, 2, "PartialAttribute")
		if err != nil {
			return err
		}
		name, err := ldapWireText(fields[0])
		if err != nil || name == "" || !ldapWireField(fields[1], ber.ClassUniversal, ber.TypeConstructed, ber.TagSet) {
			return malformedf("invalid partial attribute description or value set")
		}
		for _, value := range fields[1].Children {
			if !ldapWireField(value, ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString) {
				return malformedf("invalid binary attribute value")
			}
		}
	}
	return nil
}

func validateLDAPResponseMessage(packet *ber.Packet) error {
	operation := packet.Children[1] // Envelope validation has already bounded this.
	switch operation.Tag {
	case ApplicationSearchResultEntry:
		return validateLDAPSearchEntry(operation)
	case ApplicationSearchResultReference:
		return validateLDAPURIs(operation)
	case ApplicationIntermediateResponse:
		position := 0
		if len(operation.Children) > 0 && ldapWireField(operation.Children[0], ber.ClassContext, ber.TypePrimitive, 0) {
			name, err := packetData(operation.Children[0])
			if err != nil || !ldapWireOID(string(name)) {
				return malformedf("invalid intermediate response OID")
			}
			position++
		}
		if len(operation.Children) > position && ldapWireField(operation.Children[position], ber.ClassContext, ber.TypePrimitive, 1) {
			position++
		}
		if len(operation.Children) != position {
			return malformedf("invalid intermediate response fields")
		}
		return nil
	case ApplicationBindResponse, ApplicationSearchResultDone, ApplicationModifyResponse, ApplicationAddResponse,
		ApplicationDelResponse, ApplicationModifyDNResponse, ApplicationCompareResponse, ApplicationExtendedResponse:
		if len(operation.Children) == 0 || !ldapWireField(operation.Children[0], ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated) {
			return malformedf("LDAPResult code is not ENUMERATED")
		}
		err := GetLDAPError(packet)
		var result *Error
		if err != nil && (!errors.As(err, &result) || !result.IsServerResult()) {
			return malformedf("invalid LDAPResult: %v", err)
		}
		return nil
	default:
		return malformedf("unexpected server protocol operation")
	}
}

func validateLDAPResponseControls(controls *ber.Packet) error {
	if len(controls.Children) == 0 {
		return malformedf("empty LDAP controls sequence")
	}
	for _, control := range controls.Children {
		if !ldapWireField(control, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) {
			return malformedf("invalid LDAP control sequence")
		}
		fields, err := packetChildCount(control, 1, 3, "Control")
		if err != nil {
			return err
		}
		oid, err := ldapWireText(fields[0])
		if err != nil || !ldapWireOID(oid) {
			return malformedf("invalid LDAP control OID")
		}
		position := 1
		if len(fields) > position && ldapWireField(fields[position], ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean) {
			position++
		}
		if len(fields) > position && ldapWireField(fields[position], ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString) {
			position++
		}
		if position != len(fields) {
			return malformedf("invalid LDAP control fields")
		}
		// Decoders and descriptions may annotate control packets in place. Check
		// a bounded wire clone so request-specific decoding retains its raw shape.
		clone, err := decodeLDAPBER(control.Bytes())
		if err != nil {
			return err
		}
		if _, err := DecodeControl(clone); err != nil {
			return malformedf("invalid encoded LDAP control: %v", err)
		}
	}
	return nil
}

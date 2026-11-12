package dccloning

import (
	"bytes"
	"encoding/xml"
	"fmt"
)

const configNamespace = "uri:microsoft.com:schemas:DCCloneConfig"

// EncodeCloneConfiguration emits UTF-8 without a BOM. Only the root is
// namespace-qualified, as required by DCCloneConfigSchema.xsd. It performs no
// host/directory validation and writes no files. Empty settings omit IPSettings.
func EncodeCloneConfiguration(configuration CloneConfiguration) ([]byte, error) {
	configuration, err := configuration.normalized()
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	buffer.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
	encoder := xml.NewEncoder(&buffer)
	encoder.Indent("", "  ")
	root := xml.StartElement{Name: xml.Name{Local: "d3c:DCCloneConfig"}, Attr: []xml.Attr{{Name: xml.Name{Local: "xmlns:d3c"}, Value: configNamespace}}}
	if err := encoder.EncodeToken(root); err != nil {
		return nil, fmt.Errorf("encode clone configuration root: %w", err)
	}
	if err := encodeConfigFields(encoder, configuration); err != nil {
		return nil, fmt.Errorf("encode clone configuration fields: %w", err)
	}
	if err := encoder.EncodeToken(root.End()); err != nil {
		return nil, fmt.Errorf("encode clone configuration end: %w", err)
	}
	if err := encoder.Flush(); err != nil {
		return nil, fmt.Errorf("flush clone configuration: %w", err)
	}
	buffer.WriteByte('\n')
	return buffer.Bytes(), nil
}

func encodeConfigFields(encoder *xml.Encoder, c CloneConfiguration) error {
	for _, field := range []struct{ name, value string }{{"ComputerName", c.ComputerName}, {"SiteName", c.SiteName}} {
		if field.value != "" {
			if err := encoder.EncodeElement(field.value, xml.StartElement{Name: xml.Name{Local: field.name}}); err != nil {
				return err
			}
		}
	}
	if !c.hasIPv4() && len(c.IPv6DNSResolvers) == 0 {
		return nil
	}
	ip := xml.StartElement{Name: xml.Name{Local: "IPSettings"}}
	if err := encoder.EncodeToken(ip); err != nil {
		return err
	}
	if c.hasIPv4() {
		if err := encodeConfigFamily(encoder, c, true); err != nil {
			return err
		}
	}
	if len(c.IPv6DNSResolvers) != 0 {
		if err := encodeConfigFamily(encoder, c, false); err != nil {
			return err
		}
	}
	return encoder.EncodeToken(ip.End())
}

func encodeConfigFamily(encoder *xml.Encoder, c CloneConfiguration, ipv4 bool) error {
	name, resolvers := "IPv6Settings", c.IPv6DNSResolvers
	if ipv4 {
		name, resolvers = "IPv4Settings", c.IPv4DNSResolvers
	}
	family := xml.StartElement{Name: xml.Name{Local: name}}
	if err := encoder.EncodeToken(family); err != nil {
		return err
	}
	mode := "DynamicSettings"
	if c.Static {
		mode = "StaticSettings"
	}
	settings := xml.StartElement{Name: xml.Name{Local: mode}}
	if err := encoder.EncodeToken(settings); err != nil {
		return err
	}
	if ipv4 && c.Static {
		for _, field := range []struct{ name, value string }{{"Address", c.IPv4Address}, {"SubnetMask", c.IPv4SubnetMask}, {"DefaultGateway", c.IPv4DefaultGateway}} {
			if field.value != "" {
				if err := encoder.EncodeElement(field.value, xml.StartElement{Name: xml.Name{Local: field.name}}); err != nil {
					return err
				}
			}
		}
	}
	for _, resolver := range resolvers {
		if err := encoder.EncodeElement(resolver, xml.StartElement{Name: xml.Name{Local: "DNSResolver"}}); err != nil {
			return err
		}
	}
	if err := encoder.EncodeToken(settings.End()); err != nil {
		return err
	}
	return encoder.EncodeToken(family.End())
}

package dccloning

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const customNamespace = "uri:microsoft.com:schemas:CustomDCCloneAllowList"
const maxListBytes = 8 << 20

type element struct {
	name       xml.Name
	attributes []xml.Attr
	children   []element
	text       string
}

// ParseCustomAllowList validates the captured Microsoft custom-list structure.
// It preserves duplicate records, trims XML whitespace around names, and
// normalizes the three observed case-insensitive type tokens. Unlike the
// PowerShell wrapper, it reports invalid roots and unknown types explicitly.
func ParseCustomAllowList(data []byte) ([]Entry, error) {
	root, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	if root.name != (xml.Name{Space: customNamespace, Local: "CustomDCCloneAllowList"}) {
		return nil, fmt.Errorf("%w: custom root namespace/name", ErrInvalidList)
	}
	return parseEntries(root)
}

// ParseDefaultAllowList reads only DefaultCloneConfig/AllowList. It never
// executes the separate sysprepInformation subtree of the system file.
func ParseDefaultAllowList(data []byte) ([]Entry, error) {
	root, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	if root.name != (xml.Name{Local: "DefaultCloneConfig"}) || strings.TrimSpace(root.text) != "" {
		return nil, fmt.Errorf("%w: default root", ErrInvalidList)
	}
	var list *element
	for i := range root.children {
		child := &root.children[i]
		if child.name == (xml.Name{Local: "sysprepInformation"}) {
			continue
		}
		if child.name != (xml.Name{Local: "AllowList"}) || list != nil {
			return nil, fmt.Errorf("%w: default allow-list cardinality/child", ErrInvalidList)
		}
		list = child
	}
	if list == nil {
		return nil, fmt.Errorf("%w: missing default AllowList", ErrInvalidList)
	}
	return parseEntries(*list)
}

func parseEntries(root element) ([]Entry, error) {
	if len(root.children) == 0 || strings.TrimSpace(root.text) != "" || !namespaceAttributes(root.attributes) {
		return nil, fmt.Errorf("%w: missing Allow entries or unexpected content", ErrInvalidList)
	}
	entries := make([]Entry, 0, len(root.children))
	for _, child := range root.children {
		if child.name != (xml.Name{Local: "Allow"}) || len(child.children) != 2 || strings.TrimSpace(child.text) != "" || !namespaceAttributes(child.attributes) {
			return nil, fmt.Errorf("%w: Allow structure", ErrInvalidList)
		}
		var entry Entry
		seen := map[string]bool{}
		for _, field := range child.children {
			if field.name.Space != "" || len(field.children) != 0 || !namespaceAttributes(field.attributes) || seen[field.name.Local] {
				return nil, fmt.Errorf("%w: duplicate or qualified entry field", ErrInvalidList)
			}
			seen[field.name.Local] = true
			switch field.name.Local {
			case "Name":
				entry.Name = field.text
			case "Type":
				entry.Type = Kind(field.text)
			default:
				return nil, fmt.Errorf("%w: unknown entry field", ErrInvalidList)
			}
		}
		if !seen["Name"] || !seen["Type"] {
			return nil, fmt.Errorf("%w: missing entry field", ErrInvalidList)
		}
		entry.Name = strings.Trim(entry.Name, " \t\r\n")
		entry.Type = canonicalKind(entry.Type)
		if entry.Name == "" || entry.Type == "" {
			return nil, fmt.Errorf("%w: empty name or unknown type", ErrInvalidList)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func namespaceAttributes(attributes []xml.Attr) bool {
	for _, attribute := range attributes {
		if attribute.Name.Space != "xmlns" && attribute.Name != (xml.Name{Local: "xmlns"}) {
			return false
		}
	}
	return true
}

func parseXML(data []byte) (element, error) {
	if len(data) > maxListBytes {
		return element{}, fmt.Errorf("%w: list exceeds %d bytes", ErrInvalidList, maxListBytes)
	}
	decoded, utf16Input, err := xmlBytes(data)
	if err != nil {
		return element{}, err
	}
	d := xml.NewDecoder(bytes.NewReader(decoded))
	if utf16Input {
		d.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
			if strings.EqualFold(charset, "utf-16") || strings.EqualFold(charset, "utf-16le") || strings.EqualFold(charset, "utf-16be") {
				return input, nil
			}
			return nil, fmt.Errorf("%w: inconsistent XML encoding", ErrInvalidList)
		}
	}
	var root element
	seen := false
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return element{}, fmt.Errorf("%w: %w", ErrInvalidList, err)
		}
		switch token := token.(type) {
		case xml.StartElement:
			if seen {
				return element{}, fmt.Errorf("%w: multiple roots", ErrInvalidList)
			}
			root, err = readElement(d, token, 0)
			if err != nil {
				return element{}, err
			}
			seen = true
		case xml.Directive:
			return element{}, fmt.Errorf("%w: XML directives are not supported", ErrInvalidList)
		case xml.CharData:
			if strings.TrimSpace(string(token)) != "" {
				return element{}, fmt.Errorf("%w: text outside root", ErrInvalidList)
			}
		case xml.ProcInst:
			if token.Target != "xml" || seen {
				return element{}, fmt.Errorf("%w: processing instruction", ErrInvalidList)
			}
		}
	}
	if !seen {
		return element{}, fmt.Errorf("%w: missing root", ErrInvalidList)
	}
	return root, nil
}

func readElement(d *xml.Decoder, start xml.StartElement, depth int) (element, error) {
	result := element{name: start.Name, attributes: start.Attr}
	if depth > 32 {
		return result, fmt.Errorf("%w: XML nesting", ErrInvalidList)
	}
	var text strings.Builder
	for {
		token, err := d.Token()
		if err != nil {
			return result, fmt.Errorf("%w: %w", ErrInvalidList, err)
		}
		switch token := token.(type) {
		case xml.StartElement:
			child, err := readElement(d, token, depth+1)
			if err != nil {
				return result, err
			}
			result.children = append(result.children, child)
		case xml.CharData:
			text.Write(token)
		case xml.EndElement:
			result.text = text.String()
			return result, nil
		case xml.Directive, xml.ProcInst:
			return result, fmt.Errorf("%w: XML directive/instruction", ErrInvalidList)
		}
	}
}

func xmlBytes(data []byte) ([]byte, bool, error) {
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	if len(data) < 2 || (!bytes.HasPrefix(data, []byte{0xff, 0xfe}) && !bytes.HasPrefix(data, []byte{0xfe, 0xff})) {
		return data, false, nil
	}
	var order binary.ByteOrder = binary.LittleEndian
	if data[0] == 0xfe {
		order = binary.BigEndian
	}
	data = data[2:]
	if len(data)%2 != 0 {
		return nil, true, fmt.Errorf("%w: odd UTF-16 byte count", ErrInvalidList)
	}
	words := make([]uint16, len(data)/2)
	for i := range words {
		words[i] = order.Uint16(data[i*2:])
	}
	for i := 0; i < len(words); i++ {
		if words[i] >= 0xd800 && words[i] <= 0xdbff {
			if i+1 == len(words) || words[i+1] < 0xdc00 || words[i+1] > 0xdfff {
				return nil, true, fmt.Errorf("%w: invalid UTF-16", ErrInvalidList)
			}
			i++
		} else if words[i] >= 0xdc00 && words[i] <= 0xdfff {
			return nil, true, fmt.Errorf("%w: invalid UTF-16", ErrInvalidList)
		}
	}
	return []byte(string(utf16.Decode(words))), true, nil
}

// EncodeCustomAllowList emits namespaced custom XML, UTF-8 without a BOM.
// Empty lists are invalid under Microsoft's XSD; Generate handles no-output.
func EncodeCustomAllowList(entries []Entry) ([]byte, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: empty custom inclusion list", ErrInvalidList)
	}
	var output bytes.Buffer
	output.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
	encoder := xml.NewEncoder(&output)
	encoder.Indent("", "  ")
	root := xml.StartElement{Name: xml.Name{Local: "dc:CustomDCCloneAllowList"}, Attr: []xml.Attr{{Name: xml.Name{Local: "xmlns:dc"}, Value: customNamespace}}}
	if err := encoder.EncodeToken(root); err != nil {
		return nil, fmt.Errorf("encode root: %w", err)
	}
	for _, entry := range entries {
		if strings.Trim(entry.Name, " \t\r\n") == "" || canonicalKind(entry.Type) == "" {
			return nil, fmt.Errorf("%w: empty name or unknown type", ErrInvalidList)
		}
		allow := xml.StartElement{Name: xml.Name{Local: "Allow"}}
		if err := encoder.EncodeToken(allow); err != nil {
			return nil, fmt.Errorf("encode entry: %w", err)
		}
		for _, field := range []struct{ name, value string }{{"Name", entry.Name}, {"Type", string(entry.Type)}} {
			if !validXMLText(field.value) {
				return nil, fmt.Errorf("%w: invalid XML text in entry", ErrInvalidList)
			}
			if err := encoder.EncodeElement(field.value, xml.StartElement{Name: xml.Name{Local: field.name}}); err != nil {
				return nil, fmt.Errorf("encode field: %w", err)
			}
		}
		if err := encoder.EncodeToken(allow.End()); err != nil {
			return nil, fmt.Errorf("encode entry end: %w", err)
		}
	}
	if err := encoder.EncodeToken(root.End()); err != nil {
		return nil, fmt.Errorf("encode root end: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("finish inclusion XML: %w", err)
	}
	return bytes.ReplaceAll(output.Bytes(), []byte("\n"), []byte("\r\n")), nil
}

func canonicalKind(kind Kind) Kind {
	// Type tokens are ASCII protocol values; do not invent Unicode aliases.
	value := strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, string(kind))
	switch value {
	case "service":
		return Service
	case "program":
		return Program
	case "wow64program":
		return WoW64Program
	default:
		return ""
	}
}

func validXMLText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r != '\t' && r != '\r' && r != '\n' && (r < 0x20 || r == 0xfffe || r == 0xffff) {
			return false
		}
	}
	return true
}

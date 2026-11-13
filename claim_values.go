package activedirectory

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

var ErrClaimType = errors.New("invalid claim type definition")
var ErrClaimTypeSchema = errors.New("claim source or class is incompatible with the observed schema")
var ErrClaimTypeReferenced = errors.New("claim type has observed resource references")

type ClaimValueType int64

const (
	ClaimInt64       ClaimValueType = 1
	ClaimUInt64      ClaimValueType = 2
	ClaimString      ClaimValueType = 3
	ClaimFQBN        ClaimValueType = 4
	ClaimSID         ClaimValueType = 5
	ClaimBoolean     ClaimValueType = 6
	ClaimOctetString ClaimValueType = 16
)

func validClaimValueType(value ClaimValueType) bool {
	return value >= ClaimInt64 && value <= ClaimBoolean || value == ClaimOctetString
}

// ClaimSuggestedValue has exactly one typed value. FQBN, SID and OctetString
// suggestions use Text, matching the reference module's StringList mapping.
// Metadata is optional and retains omission separately from an empty string.
type ClaimSuggestedValue struct {
	Text                           *string
	Integer                        *int64
	Unsigned                       *uint64
	GUID, DisplayName, Description *string
}
type ClaimSuggestedValues struct {
	RawXML    string
	ValueType ClaimValueType
	Values    []ClaimSuggestedValue
	// Extensions reports valid foreign XML elements that are retained only in
	// RawXML. Existing XML is never reserialized for an unrelated update.
	Extensions bool
}

const claimValuesNamespace = "http://schemas.microsoft.com/2010/08/ActiveDirectory/PossibleValues"
const claimValuesMaxBytes = 1 << 20

func claimValuesList(valueType ClaimValueType) string {
	switch valueType {
	case ClaimInt64:
		return "IntegerList"
	case ClaimUInt64:
		return "UnsignedIntegerList"
	case ClaimString, ClaimFQBN, ClaimSID, ClaimOctetString:
		return "StringList"
	default:
		return ""
	}
}
func claimValueText(value ClaimSuggestedValue, valueType ClaimValueType) (string, error) {
	count := 0
	if value.Text != nil {
		count++
	}
	if value.Integer != nil {
		count++
	}
	if value.Unsigned != nil {
		count++
	}
	if count != 1 {
		return "", ErrClaimType
	}
	for _, field := range []*string{value.GUID, value.DisplayName, value.Description} {
		if field != nil && !validDirectoryText(*field) {
			return "", ErrClaimType
		}
	}
	switch claimValuesList(valueType) {
	case "IntegerList":
		if value.Integer != nil {
			return strconv.FormatInt(*value.Integer, 10), nil
		}
	case "UnsignedIntegerList":
		if value.Unsigned != nil {
			return strconv.FormatUint(*value.Unsigned, 10), nil
		}
	case "StringList":
		if value.Text != nil && validDirectoryText(*value.Text) {
			return *value.Text, nil
		}
	}
	return "", ErrClaimType
}
func encodeClaimValues(values []ClaimSuggestedValue, valueType ClaimValueType) (string, error) {
	list := claimValuesList(valueType)
	if list == "" || len(values) == 0 {
		return "", ErrClaimType
	}
	var out bytes.Buffer
	encoder := xml.NewEncoder(&out)
	root := xml.StartElement{Name: xml.Name{Local: "PossibleClaimValues"}, Attr: []xml.Attr{{Name: xml.Name{Local: "xmlns"}, Value: claimValuesNamespace}}}
	if err := encoder.EncodeToken(root); err != nil {
		return "", err
	}
	start := xml.StartElement{Name: xml.Name{Local: list}}
	if err := encoder.EncodeToken(start); err != nil {
		return "", err
	}
	seen := map[string]bool{}
	for _, value := range values {
		text, err := claimValueText(value, valueType)
		if err != nil {
			return "", err
		}
		key := claimFoldKey(text)
		if seen[key] {
			return "", ErrClaimType
		}
		seen[key] = true
		item := xml.StartElement{Name: xml.Name{Local: "Item"}}
		if err := encoder.EncodeToken(item); err != nil {
			return "", err
		}
		for _, field := range []struct {
			name  string
			value *string
		}{{"ValueGUID", value.GUID}, {"ValueDisplayName", value.DisplayName}, {"ValueDescription", value.Description}, {"Value", &text}} {
			if field.value != nil {
				if err := encoder.EncodeElement(*field.value, xml.StartElement{Name: xml.Name{Local: field.name}}); err != nil {
					return "", err
				}
			}
		}
		if err := encoder.EncodeToken(item.End()); err != nil {
			return "", err
		}
		if err := encoder.Flush(); err != nil {
			return "", err
		}
		if out.Len() > claimValuesMaxBytes {
			return "", ErrClaimType
		}
	}
	if err := encoder.EncodeToken(start.End()); err != nil {
		return "", err
	}
	if err := encoder.EncodeToken(root.End()); err != nil {
		return "", err
	}
	if err := encoder.Flush(); err != nil {
		return "", err
	}
	if out.Len() > claimValuesMaxBytes {
		return "", ErrClaimType
	}
	return out.String(), nil
}

// parseClaimValues enforces the reference XSD's known element cardinalities,
// sequence, namespace and numeric widths without resolving entities or DTDs.
func parseClaimValues(raw string, expected *ClaimValueType) (result ClaimSuggestedValues, err error) {
	result.RawXML = raw
	if len(raw) > claimValuesMaxBytes || !validDirectoryText(raw) {
		return result, ErrClaimType
	}
	decoder := xml.NewDecoder(strings.NewReader(raw))
	// LDAP already decoded its Unicode string to UTF-8. The module emits a
	// UTF-16 XML declaration from StringWriter; its stored text is not UTF-16 bytes.
	decoder.CharsetReader = func(charset string, r io.Reader) (io.Reader, error) {
		if strings.EqualFold(charset, "utf-16") {
			return r, nil
		}
		return nil, ErrClaimType
	}
	var stack []string
	seenFields := map[string]bool{}
	var value ClaimSuggestedValue
	var valueText string
	lastField := 0
	listSeen := false
	rootSeen := false
	for {
		token, e := decoder.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return result, errors.Join(ErrClaimType, e)
		}
		switch token := token.(type) {
		case xml.Directive:
			return result, ErrClaimType
		case xml.StartElement:
			if len(stack) == 0 {
				if rootSeen || token.Name.Space != claimValuesNamespace || token.Name.Local != "PossibleClaimValues" {
					return result, ErrClaimType
				}
				rootSeen = true
				stack = append(stack, token.Name.Local)
				continue
			}
			if token.Name.Space != claimValuesNamespace {
				if token.Name.Space == "" || !(len(stack) == 1 || len(stack) == 3 && lastField < 4) {
					return result, ErrClaimType
				}
				result.Extensions = true
				if e := decoder.Skip(); e != nil {
					return result, errors.Join(ErrClaimType, e)
				}
				continue
			}
			switch len(stack) {
			case 1:
				if listSeen {
					return result, ErrClaimType
				}
				listSeen = true
				switch token.Name.Local {
				case "IntegerList":
					result.ValueType = ClaimInt64
				case "UnsignedIntegerList":
					result.ValueType = ClaimUInt64
				case "StringList":
					result.ValueType = ClaimString
				default:
					return result, ErrClaimType
				}
				if expected != nil && claimValuesList(*expected) != token.Name.Local {
					return result, ErrClaimType
				}
			case 2:
				if token.Name.Local != "Item" {
					return result, ErrClaimType
				}
				value = ClaimSuggestedValue{}
				seenFields = map[string]bool{}
				lastField = 0
			case 3:
				order := map[string]int{"ValueGUID": 1, "ValueDisplayName": 2, "ValueDescription": 3, "Value": 4}[token.Name.Local]
				if order == 0 || order <= lastField || seenFields[token.Name.Local] {
					return result, ErrClaimType
				}
				lastField = order
				seenFields[token.Name.Local] = true
				var text string
				if e := decoder.DecodeElement(&text, &token); e != nil {
					return result, errors.Join(ErrClaimType, e)
				}
				switch token.Name.Local {
				case "ValueGUID":
					value.GUID = &text
				case "ValueDisplayName":
					value.DisplayName = &text
				case "ValueDescription":
					value.Description = &text
				case "Value":
					valueText = text
				}
				continue
			default:
				return result, ErrClaimType
			}
			stack = append(stack, token.Name.Local)
		case xml.EndElement:
			if len(stack) == 0 {
				return result, ErrClaimType
			}
			if len(stack) == 3 {
				if !seenFields["Value"] {
					return result, ErrClaimType
				}
				switch result.ValueType {
				case ClaimInt64:
					n, e := strconv.ParseInt(strings.TrimSpace(valueText), 10, 64)
					if e != nil {
						return result, errors.Join(ErrClaimType, e)
					}
					value.Integer = &n
				case ClaimUInt64:
					n, e := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(valueText), "+"), 10, 64)
					if e != nil {
						return result, errors.Join(ErrClaimType, e)
					}
					value.Unsigned = &n
				case ClaimString:
					text := valueText
					value.Text = &text
				}
				result.Values = append(result.Values, value)
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if strings.TrimSpace(string(token)) != "" {
				return result, ErrClaimType
			}
		}
	}
	if !rootSeen || len(stack) != 0 || !listSeen || len(result.Values) == 0 {
		return result, ErrClaimType
	}
	seen := map[string]bool{}
	for _, v := range result.Values {
		text, e := claimValueText(v, result.ValueType)
		if e != nil {
			return result, e
		}
		key := claimFoldKey(text)
		if seen[key] {
			return result, ErrClaimType
		}
		seen[key] = true
	}
	if expected != nil {
		result.ValueType = *expected
	}
	return result, nil
}

func claimValueTypeText(value ClaimValueType) string { return fmt.Sprint(int64(value)) }

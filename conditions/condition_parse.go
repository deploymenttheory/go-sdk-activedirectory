package conditions

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

type conditionNode struct {
	code     byte
	wire     []byte
	children []*conditionNode
}

type conditionParser struct {
	text    string
	at      int
	depth   int
	nodes   int
	options SDDLOptions
}

var binaryConditionOperators = []struct {
	text string
	code byte
}{
	{"==", 0x80},
	{"!=", 0x81},
	{"<=", 0x83},
	{">=", 0x85},
	{"<", 0x82},
	{">", 0x84},
	{"Not_Contains", 0x8e},
	{"Not_Any_of", 0x8f},
	{"Contains", 0x86},
	{"Any_of", 0x88},
}

var unaryConditionOperators = []struct {
	text string
	code byte
}{
	{"Not_Device_Member_of_Any", 0x93},
	{"Not_Device_Member_of", 0x91},
	{"Not_Member_of_Any", 0x92},
	{"Not_Member_of", 0x90},
	{"Device_Member_of_Any", 0x8c},
	{"Device_Member_of", 0x8a},
	{"Member_of_Any", 0x8b},
	{"Member_of", 0x89},
	{"Not_Exists", 0x8d},
	{"Exists", 0x87},
}

func compileCondition(text string, options SDDLOptions) ([]byte, error) {
	parser := conditionParser{text: text, options: options}
	root, err := parser.expression(0)
	if err != nil {
		return nil, err
	}
	parser.space()
	if parser.at != len(text) {
		return nil, parser.invalid("trailing expression data")
	}
	if !boundedConditionTree(root, 0) {
		return nil, parser.invalid("operator nesting")
	}
	result := appendCondition([]byte{'a', 'r', 't', 'x'}, root)
	if len(result) > 65528 {
		return nil, parser.invalid("conditional token size")
	}
	for len(result)%4 != 0 {
		result = append(result, 0)
	}
	return result, nil
}

func boundedConditionTree(node *conditionNode, depth int) bool {
	if depth >= 64 {
		return false
	}
	for _, child := range node.children {
		if !boundedConditionTree(child, depth+1) {
			return false
		}
	}
	return true
}

func appendCondition(out []byte, node *conditionNode) []byte {
	if len(node.wire) != 0 {
		return append(out, node.wire...)
	}
	for _, child := range node.children {
		out = appendCondition(out, child)
	}
	return append(out, node.code)
}

func (parser *conditionParser) invalid(reason string) error {
	return fmt.Errorf("%w: condition %s at byte %d", ErrInvalidExpression, reason, parser.at)
}

func (parser *conditionParser) space() {
	for parser.at < len(parser.text) && strings.ContainsRune(" \t\r\n\v\f", rune(parser.text[parser.at])) {
		parser.at++
	}
}

func (parser *conditionParser) take(text string) bool {
	parser.space()
	if len(parser.text)-parser.at < len(text) || !strings.EqualFold(parser.text[parser.at:parser.at+len(text)], text) {
		return false
	}
	end := parser.at + len(text)
	if len(text) != 0 && ((text[len(text)-1] >= 'A' && text[len(text)-1] <= 'Z') || (text[len(text)-1] >= 'a' && text[len(text)-1] <= 'z')) &&
		end < len(parser.text) && isSimpleAttributeByte(parser.text[end]) {
		return false
	}
	parser.at = end
	return true
}

func (parser *conditionParser) expression(level int) (*conditionNode, error) {
	if level == 2 {
		return parser.factor()
	}
	left, err := parser.expression(level + 1)
	if err != nil {
		return nil, err
	}
	op, code := "||", byte(0xa1)
	if level == 1 {
		op, code = "&&", 0xa0
	}
	for parser.take(op) {
		right, parseErr := parser.expression(level + 1)
		if parseErr != nil {
			return nil, parseErr
		}
		left = &conditionNode{code: code, children: []*conditionNode{left, right}}
	}
	return left, nil
}

func (parser *conditionParser) factor() (*conditionNode, error) {
	parser.depth++
	parser.nodes++
	defer func() { parser.depth-- }()
	if parser.depth > 64 || parser.nodes > 4096 {
		return nil, parser.invalid("complexity")
	}
	if parser.take("!") {
		operand, err := parser.factor()
		if err != nil {
			return nil, err
		}
		return &conditionNode{code: 0xa2, children: []*conditionNode{operand}}, nil
	}
	if parser.take("(") {
		inner, err := parser.expression(0)
		if err != nil {
			return nil, err
		}
		if !parser.take(")") {
			return nil, parser.invalid("closing parenthesis")
		}
		return inner, nil
	}
	for _, operator := range unaryConditionOperators {
		if !parser.take(operator.text) {
			continue
		}
		var operand *conditionNode
		var err error
		if operator.code == 0x87 || operator.code == 0x8d {
			operand, err = parser.attribute()
		} else {
			operand, err = parser.value(true)
		}
		if err != nil {
			return nil, err
		}
		if (operator.code == 0x87 || operator.code == 0x8d) && operand.code != 0xf8 && operand.code != 0xfa {
			return nil, parser.invalid("presence requires local or resource attribute")
		}
		return &conditionNode{code: operator.code, children: []*conditionNode{operand}}, nil
	}
	left, err := parser.attribute()
	if err != nil {
		return nil, err
	}
	for _, operator := range binaryConditionOperators {
		if !parser.take(operator.text) {
			continue
		}
		right, parseErr := parser.value(false)
		if parseErr != nil {
			return nil, parseErr
		}
		return &conditionNode{code: operator.code, children: []*conditionNode{left, right}}, nil
	}
	return left, nil
}

func isSimpleAttributeByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune(":./_", rune(c))
}

func (parser *conditionParser) attribute() (*conditionNode, error) {
	parser.space()
	code := byte(0xf8)
	prefixed := false
	for _, prefix := range []struct {
		name string
		code byte
	}{{"@User.", 0xf9}, {"@Resource.", 0xfa}, {"@Device.", 0xfb}} {
		if len(parser.text)-parser.at >= len(prefix.name) && strings.EqualFold(parser.text[parser.at:parser.at+len(prefix.name)], prefix.name) {
			parser.at += len(prefix.name)
			code, prefixed = prefix.code, true
			break
		}
	}
	var name []byte
	start := parser.at
	for parser.at < len(parser.text) {
		c := parser.text[parser.at]
		if prefixed && c == '%' {
			if len(parser.text)-parser.at < 5 {
				return nil, parser.invalid("attribute escape")
			}
			value, err := strconv.ParseUint(parser.text[parser.at+1:parser.at+5], 16, 16)
			if err != nil || value == 0 {
				return nil, parser.invalid("attribute escape")
			}
			name = binary.LittleEndian.AppendUint16(name, uint16(value))
			parser.at += 5
			continue
		}
		allowed := isSimpleAttributeByte(c) || c == '@' || (prefixed && (c >= 0x80 || strings.ContainsRune("#$'*+-;?@[\\]^`{}~", rune(c))))
		if !allowed {
			break
		}
		char, size := utf8.DecodeRuneInString(parser.text[parser.at:])
		for _, word := range utf16.Encode([]rune{char}) {
			name = binary.LittleEndian.AppendUint16(name, word)
		}
		parser.at += size
	}
	if parser.at == start || (!prefixed && parser.text[start] == '@') {
		return nil, parser.invalid("attribute name")
	}
	if _, err := decodeUTF16(name); err != nil {
		return nil, parser.invalid("attribute Unicode")
	}
	return conditionLeaf(code, name)
}

func (parser *conditionParser) value(sids bool) (*conditionNode, error) {
	parser.space()
	if parser.at >= len(parser.text) {
		return nil, parser.invalid("missing operand")
	}
	if parser.take("{") {
		var data []byte
		for count := 0; ; count++ {
			if count >= 4096 {
				return nil, parser.invalid("composite size")
			}
			item, err := parser.scalar(sids)
			if err != nil {
				return nil, err
			}
			data = append(data, item.wire...)
			if parser.take("}") {
				return conditionLeaf(0x50, data)
			}
			if !parser.take(",") {
				return nil, parser.invalid("composite separator")
			}
		}
	}
	if !sids && parser.text[parser.at] == '@' {
		return parser.attribute()
	}
	return parser.scalar(sids)
}

func (parser *conditionParser) scalar(sids bool) (*conditionNode, error) {
	parser.space()
	if parser.at >= len(parser.text) {
		return nil, parser.invalid("missing literal")
	}
	if sids || (len(parser.text)-parser.at >= 4 && strings.EqualFold(parser.text[parser.at:parser.at+4], "SID(")) {
		if !parser.take("SID(") {
			return nil, parser.invalid("SID literal")
		}
		end := strings.IndexByte(parser.text[parser.at:], ')')
		if end < 0 {
			return nil, parser.invalid("SID closing parenthesis")
		}
		sid, err := parseSDDLSID(parser.text[parser.at:parser.at+end], parser.options)
		if err != nil {
			return nil, err
		}
		parser.at += end + 1
		return conditionLeaf(0x51, sid)
	}
	if parser.text[parser.at] == '"' {
		parser.at++
		start := parser.at
		for parser.at < len(parser.text) && parser.text[parser.at] != '"' {
			parser.at++
		}
		if parser.at == len(parser.text) {
			return nil, parser.invalid("unclosed string")
		}
		data := encodeUTF16(parser.text[start:parser.at], false)
		parser.at++
		return conditionLeaf(0x10, data)
	}
	start := parser.at
	for parser.at < len(parser.text) && !strings.ContainsRune(" \t\r\n,})(&|=!<>", rune(parser.text[parser.at])) {
		parser.at++
	}
	text := parser.text[start:parser.at]
	if strings.HasPrefix(text, "#") {
		data, err := hex.DecodeString(text[1:])
		if err != nil {
			return nil, parser.invalid("octet literal")
		}
		return conditionLeaf(0x18, data)
	}
	data, err := conditionInteger(text)
	if err != nil {
		return nil, err
	}
	return &conditionNode{code: 4, wire: data}, nil
}

func conditionInteger(text string) ([]byte, error) {
	sign, base := byte(3), byte(2)
	if strings.HasPrefix(text, "+") || strings.HasPrefix(text, "-") {
		if text[0] == '+' {
			sign = 1
		} else {
			sign = 2
		}
		text = text[1:]
	}
	radix := 10
	if strings.HasPrefix(text, "0x") || strings.HasPrefix(text, "0X") {
		radix, base, text = 16, 3, text[2:]
	} else if len(text) >= 1 && text[0] == '0' {
		radix, base = 8, 1
	}
	value, err := strconv.ParseUint(text, radix, 64)
	if err != nil || (sign == 2 && value > 1<<63) || (sign == 1 && value > 1<<63-1) {
		return nil, fmt.Errorf("%w: integer literal", ErrInvalidExpression)
	}
	if sign == 2 {
		value = ^value + 1
	}
	result := make([]byte, 11)
	result[0], result[9], result[10] = 4, sign, base
	binary.LittleEndian.PutUint64(result[1:9], value)
	return result, nil
}

func encodeUTF16(text string, terminated bool) []byte {
	words := utf16.Encode([]rune(text))
	result := make([]byte, 0, 2*len(words)+2)
	for _, word := range words {
		result = binary.LittleEndian.AppendUint16(result, word)
	}
	if terminated {
		result = append(result, 0, 0)
	}
	return result
}

func conditionLeaf(code byte, data []byte) (*conditionNode, error) {
	length := len(data)
	if length < 0 || length > 65535 {
		return nil, fmt.Errorf("%w: conditional payload length", ErrInvalidExpression)
	}
	result := make([]byte, 5, 5+len(data))
	result[0] = code
	binary.LittleEndian.PutUint32(result[1:5], uint32(length))
	return &conditionNode{code: code, wire: append(result, data...)}, nil
}

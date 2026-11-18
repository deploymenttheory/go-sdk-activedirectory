package ldap

import (
	"bytes"
	"crypto/md5" // #nosec G501 -- Retained upstream DIGEST-MD5 API; SDK portable auth never selects this mechanism.
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Azure/go-ntlmssp"
	ber "github.com/go-asn1-ber/asn1-ber"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3/gssapi"
)

// SimpleBindRequest represents a username/password bind operation
type SimpleBindRequest struct {
	// Username is the name of the Directory object that the client wishes to bind as
	Username string
	// Password is the credentials to bind with
	Password string
	// Controls are optional controls to send with the bind request
	Controls []Control
	// AllowEmptyPassword sets whether the client allows binding with an empty password
	// (normally used for unauthenticated bind).
	AllowEmptyPassword bool
}

// SimpleBindResult contains the response from the server
type SimpleBindResult struct {
	Controls []Control
}

// NewSimpleBindRequest returns a bind request
func NewSimpleBindRequest(username string, password string, controls []Control) *SimpleBindRequest {
	return &SimpleBindRequest{
		Username:           username,
		Password:           password,
		Controls:           controls,
		AllowEmptyPassword: false,
	}
}

func (req *SimpleBindRequest) appendTo(envelope *ber.Packet) error {
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, req.Username, "User Name"))
	pkt.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, req.Password, "Password"))

	envelope.AppendChild(pkt)
	if len(req.Controls) > 0 {
		envelope.AppendChild(encodeControls(req.Controls))
	}

	return nil
}

// SimpleBind performs the simple bind operation defined in the given request
func (l *Conn) SimpleBind(simpleBindRequest *SimpleBindRequest) (*SimpleBindResult, error) {
	if simpleBindRequest.Password == "" && !simpleBindRequest.AllowEmptyPassword {
		return nil, NewError(ErrorEmptyPassword, errors.New("ldap: empty password not allowed by the client"))
	}

	msgCtx, err := l.doRequest(simpleBindRequest)
	if err != nil {
		return nil, err
	}
	defer l.finishMessage(msgCtx)

	packet, err := l.readPacket(msgCtx)
	if err != nil {
		return nil, err
	}

	return decodeSimpleBindResult(packet)
}

// decodeSimpleBindResult decodes a bind response envelope, including any
// response controls. It is separated from the network loop so the full
// response decoder can be fuzzed directly.
func decodeSimpleBindResult(packet *ber.Packet) (*SimpleBindResult, error) {
	result := &SimpleBindResult{
		Controls: make([]Control, 0),
	}

	controls, ok, err := packetChildIfPresent(packet, 2)
	if err != nil {
		return nil, err
	}
	if ok {
		for _, child := range controls.Children {
			decodedChild, decodeErr := DecodeControl(child)
			if decodeErr != nil {
				return nil, fmt.Errorf("failed to decode child control: %w", decodeErr)
			}
			result.Controls = append(result.Controls, decodedChild)
		}
	}

	err = GetLDAPError(packet)
	return result, err
}

// Bind performs a bind with the given username and password.
//
// It does not allow unauthenticated bind (i.e. empty password). Use the UnauthenticatedBind method
// for that.
func (l *Conn) Bind(username, password string) error {
	req := &SimpleBindRequest{
		Username:           username,
		Password:           password,
		AllowEmptyPassword: false,
	}
	_, err := l.SimpleBind(req)
	return err
}

// UnauthenticatedBind performs an unauthenticated bind.
//
// A username may be provided for trace (e.g. logging) purpose only, but it is normally not
// authenticated or otherwise validated by the LDAP server.
//
// See https://tools.ietf.org/html/rfc4513#section-5.1.2 .
// See https://tools.ietf.org/html/rfc4513#section-6.3.1 .
func (l *Conn) UnauthenticatedBind(username string) error {
	req := &SimpleBindRequest{
		Username:           username,
		Password:           "",
		AllowEmptyPassword: true,
	}
	_, err := l.SimpleBind(req)
	return err
}

// DigestMD5BindRequest represents a digest-md5 bind operation
type DigestMD5BindRequest struct {
	Host string
	// Username is the name of the Directory object that the client wishes to bind as
	Username string
	// Password is the credentials to bind with
	Password string
	// Controls are optional controls to send with the bind request
	Controls []Control
}

func (req *DigestMD5BindRequest) appendTo(envelope *ber.Packet) error {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "User Name"))

	auth := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, "", "authentication")
	auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "DIGEST-MD5", "SASL Mech"))
	request.AppendChild(auth)
	envelope.AppendChild(request)
	if len(req.Controls) > 0 {
		envelope.AppendChild(encodeControls(req.Controls))
	}
	return nil
}

// DigestMD5BindResult contains the response from the server
type DigestMD5BindResult struct {
	Controls []Control
}

// MD5Bind performs a digest-md5 bind with the given host, username and password.
func (l *Conn) MD5Bind(host, username, password string) error {
	req := &DigestMD5BindRequest{
		Host:     host,
		Username: username,
		Password: password,
	}
	_, err := l.DigestMD5Bind(req)
	return err
}

// DigestMD5Bind performs the digest-md5 bind operation defined in the given request
func (l *Conn) DigestMD5Bind(digestMD5BindRequest *DigestMD5BindRequest) (*DigestMD5BindResult, error) {
	if digestMD5BindRequest.Password == "" {
		return nil, NewError(ErrorEmptyPassword, errors.New("ldap: empty password not allowed by the client"))
	}

	msgCtx, err := l.doRequest(digestMD5BindRequest)
	if err != nil {
		return nil, err
	}
	defer l.finishMessage(msgCtx)

	packet, err := l.readPacket(msgCtx)
	if err != nil {
		return nil, err
	}
	l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if l.Debug {
		if err = addLDAPDescriptions(packet); err != nil {
			return nil, err
		}
		ber.PrintPacket(packet)
	}

	result := &DigestMD5BindResult{
		Controls: make([]Control, 0),
	}
	var params map[string]string
	_, hasControls, err := packetChildIfPresent(packet, 2)
	if err != nil {
		return nil, err
	}
	if !hasControls {
		challenge, perr := packetChild(packet, 1)
		if perr == nil {
			challengeChild, hasChallengeChild, cerr := packetChildIfPresent(challenge, 3)
			if cerr != nil {
				return result, GetLDAPError(packet)
			}
			if hasChallengeChild {
				child, perr := packetChild(challenge, 0)
				if perr != nil || child.Tag != ber.TagEnumerated {
					return result, GetLDAPError(packet)
				}
				code, perr := packetInt64(child)
				if perr != nil || code != 14 {
					return result, GetLDAPError(packet)
				}
				child = challengeChild
				if child.Tag != ber.TagObjectDescriptor || child.Data == nil {
					return result, GetLDAPError(packet)
				}
				data, _ := io.ReadAll(child.Data)
				params, err = parseParams(string(data))
				if err != nil {
					return result, fmt.Errorf("parsing digest-challenge: %w", err)
				}
			}
		}
	}

	if len(params) > 0 {
		resp, err := computeResponse(
			params,
			"ldap/"+strings.ToLower(digestMD5BindRequest.Host),
			digestMD5BindRequest.Username,
			digestMD5BindRequest.Password,
		)
		if err != nil {
			return nil, fmt.Errorf("compute digest-md5 response: %w", err)
		}
		packet = ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, l.nextMessageID(), "MessageID"))

		request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
		request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
		request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "User Name"))

		auth := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, "", "authentication")
		auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "DIGEST-MD5", "SASL Mech"))
		auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, resp, "Credentials"))
		request.AppendChild(auth)
		packet.AppendChild(request)
		msgCtx, err = l.sendMessage(packet)
		if err != nil {
			return nil, fmt.Errorf("send message: %w", err)
		}
		defer l.finishMessage(msgCtx)
		packetResponse, ok := <-msgCtx.responses
		if !ok {
			return nil, NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
		}
		packet, err = packetResponse.ReadPacket()
		l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
		if err != nil {
			return nil, fmt.Errorf("read packet: %w", err)
		}

		_, hasControls, err := packetChildIfPresent(packet, 2)
		if err != nil {
			return nil, err
		}
		if !hasControls {
			response, rerr := packetChild(packet, 1)
			if rerr != nil {
				return result, GetLDAPError(packet)
			}
			if response.ClassType == ber.ClassApplication && response.TagType == ber.TypeConstructed {
				if _, rerr := packetChildCount(response, 3, -1, "bind response"); rerr == nil {
					resultCodeChild, rerr := packetChild(response, 0)
					if rerr != nil {
						return result, GetLDAPError(packet)
					}
					if resultCodeChild.Tag == ber.TagInteger || resultCodeChild.Tag == ber.TagEnumerated {
						resultCode, rerr := packetResultCode(resultCodeChild)
						if rerr != nil {
							return result, GetLDAPError(packet)
						}
						if resultCode == 14 {
							msgCtx, err := l.doRequest(digestMD5BindRequest)
							if err != nil {
								return nil, err
							}
							defer l.finishMessage(msgCtx)
							packetResponse, ok := <-msgCtx.responses
							if !ok {
								return nil, NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
							}
							packet, err = packetResponse.ReadPacket()
							l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
							if err != nil {
								return nil, fmt.Errorf("read packet: %w", err)
							}
						}
					}
				} else {
					return result, GetLDAPError(packet)
				}
			}
		}
	}

	err = GetLDAPError(packet)
	return result, err
}

func parseParams(str string) (map[string]string, error) {
	m := make(map[string]string)
	var key, value string
	var state int
	var escaped bool
	for i := 0; i <= len(str); i++ {
		switch state {
		case 0: // reading key
			if i == len(str) {
				return nil, fmt.Errorf("syntax error on %d", i)
			}
			// The digest-challenge is an RFC 2068 #rule (RFC 2831 section 2.1.1),
			// which permits optional linear whitespace around the comma directive
			// separators. Directive names are tokens that never contain
			// whitespace, so skip it here; otherwise a directive following
			// "..., name" is keyed with a leading space and the lookups in
			// computeResponse (realm, nonce, authzid) miss it.
			if str[i] == ' ' || str[i] == '\t' {
				continue
			}
			if str[i] != '=' {
				key += string(str[i])
				continue
			}
			state = 1
		case 1: // reading value
			if i == len(str) {
				m[key] = value
				break
			}
			// Linear whitespace outside a quoted string is not part of the
			// value: an unquoted value is a token and a quoted value's content
			// is read in the quoted state below. Skipping it lets a challenge
			// using the whitespace the #rule allows (e.g. `nonce="n" , qop=auth`)
			// parse the same as the unspaced form.
			if str[i] == ' ' || str[i] == '\t' {
				continue
			}
			switch str[i] {
			case ',':
				m[key] = value
				state = 0
				key = ""
				value = ""
			case '"':
				if value != "" {
					return nil, fmt.Errorf("syntax error on %d", i)
				}
				state = 2
			default:
				value += string(str[i])
			}
		case 2: // inside quotes
			if i == len(str) {
				return nil, fmt.Errorf("syntax error on %d", i)
			}
			switch {
			case escaped:
				// RFC 2831 section 7.1 quoted-pair: a backslash escapes the
				// following character, so the next byte is taken literally
				// (this is how a server sends a literal " or \ in a realm or
				// nonce).
				value += string(str[i])
				escaped = false
			case str[i] == '\\':
				escaped = true
			case str[i] == '"':
				state = 1
			default:
				value += string(str[i])
			}
		}
	}
	return m, nil
}

func computeResponse(params map[string]string, uri, username, password string) (string, error) {
	nc := "00000001"
	qop := "auth"
	rb, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	cnonce := hex.EncodeToString(rb)
	x := username + ":" + params["realm"] + ":" + password
	y := md5Hash([]byte(x))

	a1 := bytes.NewBuffer(y)
	a1.WriteString(":" + params["nonce"] + ":" + cnonce)
	if len(params["authzid"]) > 0 {
		a1.WriteString(":" + params["authzid"])
	}
	a2 := bytes.NewBuffer([]byte("AUTHENTICATE"))
	a2.WriteString(":" + uri)
	ha1 := hex.EncodeToString(md5Hash(a1.Bytes()))
	ha2 := hex.EncodeToString(md5Hash(a2.Bytes()))

	kd := ha1
	kd += ":" + params["nonce"]
	kd += ":" + nc
	kd += ":" + cnonce
	kd += ":" + qop
	kd += ":" + ha2
	resp := hex.EncodeToString(md5Hash([]byte(kd)))
	return fmt.Sprintf(
		`username="%s",realm="%s",nonce="%s",cnonce="%s",nc=00000001,qop=%s,digest-uri="%s",response=%s`,
		quotedStringEscape(username),
		quotedStringEscape(params["realm"]),
		quotedStringEscape(params["nonce"]),
		cnonce,
		qop,
		quotedStringEscape(uri),
		resp,
	), nil
}

// quotedStringEscape escapes the two characters that may not appear unescaped
// inside a DIGEST-MD5 quoted string per RFC 2831 section 7.1: the backslash
// and the double quote. The backslash is replaced first so the quotes escaped
// afterwards are not doubled.
func quotedStringEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

func md5Hash(b []byte) []byte {
	hasher := md5.New() // #nosec G401 -- RFC 2831 DIGEST-MD5 compatibility only; unavailable through SDK authentication.
	hasher.Write(b)
	return hasher.Sum(nil)
}

func randomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

var externalBindRequest = requestFunc(func(envelope *ber.Packet) error {
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "User Name"))

	saslAuth := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, "", "authentication")
	saslAuth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "EXTERNAL", "SASL Mech"))
	saslAuth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "SASL Cred"))

	pkt.AppendChild(saslAuth)

	envelope.AppendChild(pkt)

	return nil
})

// ExternalBind performs SASL/EXTERNAL authentication.
//
// Use ldap.DialURL("ldapi://") to connect to the Unix socket before ExternalBind.
//
// See https://tools.ietf.org/html/rfc4422#appendix-A
func (l *Conn) ExternalBind() error {
	msgCtx, err := l.doRequest(externalBindRequest)
	if err != nil {
		return err
	}
	defer l.finishMessage(msgCtx)

	packet, err := l.readPacket(msgCtx)
	if err != nil {
		return err
	}

	return GetLDAPError(packet)
}

// NTLMBind performs an NTLMSSP bind leveraging https://github.com/Azure/go-ntlmssp

// NTLMBindRequest represents an NTLMSSP bind operation
type NTLMBindRequest struct {
	// Domain is the AD Domain to authenticate too. If not specified, it will be grabbed from the NTLMSSP Challenge
	Domain string
	// Username is the name of the Directory object that the client wishes to bind as
	Username string
	// Password is the credentials to bind with
	Password string
	// AllowEmptyPassword sets whether the client allows binding with an empty password
	// (normally used for unauthenticated bind).
	AllowEmptyPassword bool
	// Hash is the hex NTLM hash to bind with. Password or hash must be provided
	Hash string
	// Controls are optional controls to send with the bind request
	Controls []Control
	// Negotiator allows to specify a custom NTLM negotiator.
	Negotiator NTLMNegotiator
}

// NTLMNegotiator is an abstraction of an NTLM implementation that produces and
// processes NTLM binary tokens.
type NTLMNegotiator interface {
	Negotiate(domain string, workstation string) ([]byte, error)
	ChallengeResponse(challenge []byte, username string, hash string) ([]byte, error)
}

func (req *NTLMBindRequest) appendTo(envelope *ber.Packet) (err error) {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "User Name"))

	var negMessage []byte

	// generate an NTLMSSP Negotiation message for the  specified domain (it can be blank)
	switch req.Negotiator {
	case nil:
		negMessage, err = ntlmssp.NewNegotiateMessage(req.Domain, "")
		if err != nil {
			return fmt.Errorf("create NTLM negotiate message: %w", err)
		}
	default:
		negMessage, err = req.Negotiator.Negotiate(req.Domain, "")
		if err != nil {
			return fmt.Errorf("create NTLM negotiate message with custom negotiator: %w", err)
		}
	}

	// append the generated NTLMSSP message as a TagEnumerated BER value
	auth := ber.Encode(ber.ClassContext, ber.TypePrimitive, ber.TagEnumerated, negMessage, "authentication")
	request.AppendChild(auth)
	envelope.AppendChild(request)
	if len(req.Controls) > 0 {
		envelope.AppendChild(encodeControls(req.Controls))
	}
	return nil
}

// NTLMBindResult contains the response from the server
type NTLMBindResult struct {
	Controls []Control
}

// NTLMBind performs an NTLMSSP Bind with the given domain, username and password
func (l *Conn) NTLMBind(domain, username, password string) error {
	req := &NTLMBindRequest{
		Domain:   domain,
		Username: username,
		Password: password,
	}
	_, err := l.NTLMChallengeBind(req)
	return err
}

// NTLMUnauthenticatedBind performs an bind with an empty password.
//
// A username is required. Anonymous bind is unsupported by go-ntlmssp.
// https://github.com/Azure/go-ntlmssp/blob/819c794454d067543bc61d29f61fef4b3c3df62c/authenticate_message.go#L87
//
// See https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4 part 3.2.5.1.2
func (l *Conn) NTLMUnauthenticatedBind(domain, username string) error {
	req := &NTLMBindRequest{
		Domain:             domain,
		Username:           username,
		Password:           "",
		AllowEmptyPassword: true,
	}
	_, err := l.NTLMChallengeBind(req)
	return err
}

// NTLMBindWithHash performs an NTLM Bind with an NTLM hash instead of plaintext password (pass-the-hash)
func (l *Conn) NTLMBindWithHash(domain, username, hash string) error {
	req := &NTLMBindRequest{
		Domain:   domain,
		Username: username,
		Hash:     hash,
	}
	_, err := l.NTLMChallengeBind(req)
	return err
}

// NTLMChallengeBind performs the NTLMSSP bind operation defined in the given request
func (l *Conn) NTLMChallengeBind(ntlmBindRequest *NTLMBindRequest) (*NTLMBindResult, error) {
	if !ntlmBindRequest.AllowEmptyPassword && ntlmBindRequest.Password == "" && ntlmBindRequest.Hash == "" {
		return nil, NewError(ErrorEmptyPassword, errors.New("ldap: empty password not allowed by the client"))
	}

	msgCtx, err := l.doRequest(ntlmBindRequest)
	if err != nil {
		return nil, err
	}
	defer l.finishMessage(msgCtx)
	packet, err := l.readPacket(msgCtx)
	if err != nil {
		return nil, err
	}
	l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if l.Debug {
		if err = addLDAPDescriptions(packet); err != nil {
			return nil, err
		}
		ber.PrintPacket(packet)
	}
	result := &NTLMBindResult{
		Controls: make([]Control, 0),
	}
	var ntlmsspChallenge []byte

	// now find the NTLM Response Message
	_, hasControls, err := packetChildIfPresent(packet, 2)
	if err != nil {
		return nil, err
	}
	if !hasControls {
		protocolOp, perr := packetChild(packet, 1)
		if perr == nil {
			protocolOpChildren, cerr := packetChildCount(protocolOp, 3, -1, "bind response")
			if cerr != nil {
				return result, GetLDAPError(packet)
			}
			if len(protocolOpChildren) == 3 {
				child, perr := packetChild(protocolOp, 1)
				if perr != nil {
					return result, GetLDAPError(packet)
				}
				ntlmsspChallenge = child.ByteValue
				// Check to make sure we got the right message. It will always start with NTLMSSP
				if len(ntlmsspChallenge) < 7 || !bytes.Equal(ntlmsspChallenge[:7], []byte("NTLMSSP")) {
					return result, GetLDAPError(packet)
				}
				l.Debug.Printf("%d: found ntlmssp challenge", msgCtx.id)
			}
		}
	}
	if ntlmsspChallenge != nil {
		var err error
		var responseMessage []byte

		switch {
		case ntlmBindRequest.Hash == "" && ntlmBindRequest.Password == "" && !ntlmBindRequest.AllowEmptyPassword:
			err = fmt.Errorf("need a password or hash to generate reply")
		case ntlmBindRequest.Negotiator == nil && ntlmBindRequest.Hash != "":
			responseMessage, err = ntlmssp.NewAuthenticateMessage(ntlmsspChallenge, ntlmBindRequest.Username, ntlmBindRequest.Hash, &ntlmssp.AuthenticateMessageOptions{
				PasswordHashed: true,
			})
		case ntlmBindRequest.Negotiator == nil && (ntlmBindRequest.Password != "" || ntlmBindRequest.AllowEmptyPassword):
			// generate a response message to the challenge with the given Username/Password if password is provided
			responseMessage, err = ntlmssp.NewAuthenticateMessage(ntlmsspChallenge, ntlmBindRequest.Username, ntlmBindRequest.Password, nil)
		default:
			hash := ntlmBindRequest.Hash
			if len(hash) == 0 {
				hash = ntHash(ntlmBindRequest.Password)
			}

			responseMessage, err = ntlmBindRequest.Negotiator.ChallengeResponse(ntlmsspChallenge, ntlmBindRequest.Username, hash)
		}

		if err != nil {
			return result, fmt.Errorf("process NTLM challenge: %w", err)
		}

		packet = ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, l.nextMessageID(), "MessageID"))

		request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
		request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
		request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "User Name"))

		// append the challenge response message as a TagEmbeddedPDV BER value
		auth := ber.Encode(ber.ClassContext, ber.TypePrimitive, ber.TagEmbeddedPDV, responseMessage, "authentication")

		request.AppendChild(auth)
		packet.AppendChild(request)
		msgCtx, err = l.sendMessage(packet)
		if err != nil {
			return nil, fmt.Errorf("send message: %w", err)
		}
		defer l.finishMessage(msgCtx)
		packetResponse, ok := <-msgCtx.responses
		if !ok {
			return nil, NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
		}
		packet, err = packetResponse.ReadPacket()
		l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
		if err != nil {
			return nil, fmt.Errorf("read packet: %w", err)
		}

	}

	err = GetLDAPError(packet)
	return result, err
}

// GSSAPIClient interface is used as the client-side implementation for the
// GSSAPI SASL mechanism.
// Interface inspired by GSSAPIClient from golang.org/x/crypto/ssh
type GSSAPIClient interface {
	// InitSecContext initiates the establishment of a security context for
	// GSS-API between the client and server.
	// Initially the token parameter should be specified as nil.
	// The routine may return a outputToken which should be transferred to
	// the server, where the server will present it to AcceptSecContext.
	// If no token need be sent, InitSecContext will indicate this by setting
	// needContinue to false. To complete the context
	// establishment, one or more reply tokens may be required from the server;
	// if so, InitSecContext will return a needContinue which is true.
	// In this case, InitSecContext should be called again when the
	// reply token is received from the server, passing the reply token
	// to InitSecContext via the token parameters.
	// See RFC 4752 section 3.1.
	InitSecContext(target string, token []byte) (outputToken []byte, needContinue bool, err error)
	// InitSecContextWithOptions is the same as InitSecContext but allows for additional options to be passed to the context establishment.
	// See RFC 4752 section 3.1.
	InitSecContextWithOptions(target string, token []byte, options []int) (outputToken []byte, needContinue bool, err error)
	// NegotiateSaslAuth performs the last step of the Sasl handshake.
	// It takes a token, which, when unwrapped, describes the servers supported
	// security layers (first octet) and maximum receive buffer (remaining
	// three octets).
	// If the received token is unacceptable an error must be returned to abort
	// the handshake.
	// Outputs a signed token describing the client's selected security layer
	// and receive buffer size and optionally an authorization identity.
	// The returned token will be sent to the server and the handshake considered
	// completed successfully and the server authenticated.
	// See RFC 4752 section 3.1.
	NegotiateSaslAuth(token []byte, authzid string) ([]byte, error)
	// DeleteSecContext destroys any established secure context.
	DeleteSecContext() error
}

// GSSAPIBindRequest represents a GSSAPI SASL mechanism bind request.
// See rfc4752 and rfc4513 section 5.2.1.2.
type GSSAPIBindRequest struct {
	// Service Principal Name user for the service ticket. Eg. "ldap/<host>"
	ServicePrincipalName string
	// (Optional) Authorization entity
	AuthZID string
	// (Optional) Controls to send with the bind request
	Controls       []Control
	SASLSecurity   SASLSecurityMode
	ChannelBinding bool
}

// GSSAPIBindResult contains keyless observations captured before the mechanism
// context is deleted. ProtectionEstablished requires final LDAP acceptance and
// installation of the exact authenticated security layer, including no layer.
type GSSAPIBindResult struct {
	Authentication        gssapi.AuthenticationContext
	SASLSecurity          SASLSecurityMode
	ProtectionEstablished bool
	SASLCipherBits        uint32
	SASLEncryptionType    int32
}

// GSSAPIBind performs the GSSAPI SASL bind using the provided GSSAPI client.
func (l *Conn) GSSAPIBind(client GSSAPIClient, servicePrincipal, authzid string) error {
	return l.GSSAPIBindRequest(client, &GSSAPIBindRequest{
		ServicePrincipalName: servicePrincipal,
		AuthZID:              authzid,
	})
}

// GSSAPIBindRequest performs the GSSAPI SASL bind using the provided GSSAPI client.
func (l *Conn) GSSAPIBindRequest(client GSSAPIClient, req *GSSAPIBindRequest) error {
	return l.GSSAPIBindRequestWithAPOptions(client, req, []int{})
}

// GSSAPIBindRequestWithAPOptions performs the GSSAPI SASL bind using the provided GSSAPI client and AP options.
func (l *Conn) GSSAPIBindRequestWithAPOptions(client GSSAPIClient, req *GSSAPIBindRequest, APOptions []int) (err error) {
	_, err = l.gssapiBindRequest(client, req, APOptions, false)
	return err
}

// GSSAPIBindRequestWithResult binds and returns authenticated observations. A
// custom GSSAPI client must expose AuthenticationContext; requested options and
// a successful LDAP result alone never establish these observations.
func (l *Conn) GSSAPIBindRequestWithResult(client GSSAPIClient, req *GSSAPIBindRequest, apOptions []int) (*GSSAPIBindResult, error) {
	return l.gssapiBindRequest(client, req, apOptions, true)
}

func (l *Conn) gssapiBindRequest(client GSSAPIClient, req *GSSAPIBindRequest, apOptions []int, requireObservation bool) (result *GSSAPIBindResult, err error) {
	if client == nil || req == nil || (req.SASLSecurity != SASLSecurityNone && req.SASLSecurity != SASLSecuritySign && req.SASLSecurity != SASLSecuritySeal) {
		return nil, fmt.Errorf("ldap: invalid GSSAPI bind request")
	}
	//nolint:errcheck
	defer client.DeleteSecContext()
	defer func() {
		if err != nil {
			_ = l.Close()
		}
	}()

	// RFC4513 section5.2.1.6 permits a SASL layer above TLS. Both independent
	// layers remain active; an explicit SASL request is never weakened by TLS.
	saslMode := req.SASLSecurity
	useSASL := saslMode != SASLSecurityNone
	type authenticationObserver interface {
		AuthenticationContext() (gssapi.AuthenticationContext, error)
	}
	observer, observable := client.(authenticationObserver)
	if requireObservation && !observable {
		return nil, fmt.Errorf("ldap: GSSAPI client cannot report authenticated mechanism state")
	}

	// Plumb the requested SASL security layer into the client so that the
	// security-layer byte sent during NegotiateSaslAuth matches the wrapping
	// installed below. Type assertion keeps the GSSAPIClient interface
	// stable for callers with custom implementations.
	type saslSecuritySetter interface {
		SetSASLSecurity(mode int)
	}
	if s, ok := client.(saslSecuritySetter); ok {
		s.SetSASLSecurity(int(saslMode))
	} else if useSASL {
		return nil, fmt.Errorf("ldap: GSSAPI client does not support SASL security layer negotiation")
	}

	if req.ChannelBinding {
		type channelBindingSetter interface {
			SetChannelBinding(cert *x509.Certificate) error
		}
		cs, ok := client.(channelBindingSetter)
		if !ok {
			return nil, fmt.Errorf("ldap: GSSAPI client does not support channel binding")
		}
		cert, certErr := l.tlsServerCertificate()
		if certErr != nil {
			return nil, certErr
		}
		if err := cs.SetChannelBinding(cert); err != nil {
			return nil, err
		}
	}

	var reqToken []byte
	var recvToken []byte
	needInit := true
	saslPhase := false // true once we enter NegotiateSaslAuth
	for {
		if needInit {
			// Establish secure context between client and server.
			reqToken, needInit, err = client.InitSecContextWithOptions(req.ServicePrincipalName, recvToken, apOptions)
			if err != nil {
				return nil, err
			}
		} else {
			// Secure context is set up, perform the last step of SASL handshake.
			saslPhase = true
			reqToken, err = client.NegotiateSaslAuth(recvToken, req.AuthZID)
			if err != nil {
				return nil, err
			}
		}

		// Only use startTLS on the NegotiateSaslAuth exchange (not the
		// final InitSecContext exchange) so the reader goroutine stays
		// alive for the AP-REP round trip.
		var flags sendMessageFlags
		if saslPhase && useSASL {
			flags = startTLS
		}

		// Send Bind request containing the current token and extract the
		// token sent by server.
		var accepted bool
		recvToken, accepted, err = l.saslBindTokenExchangeResult(req.Controls, reqToken, flags)
		if err != nil {
			return nil, err
		}

		if accepted {
			if !saslPhase || len(recvToken) != 0 {
				return nil, fmt.Errorf("ldap: GSSAPI bind succeeded before authenticated layer negotiation completed")
			}
			break
		}
		if saslPhase {
			return nil, fmt.Errorf("ldap: GSSAPI security-layer selection was not accepted")
		}
	}
	result = &GSSAPIBindResult{SASLSecurity: saslMode}
	if observable {
		result.Authentication, err = observer.AuthenticationContext()
		if err != nil {
			return nil, err
		}
		if !result.Authentication.Complete || !result.Authentication.MutualAuthentication || result.Authentication.SASLSecurity != int(saslMode) {
			return nil, fmt.Errorf("ldap: authenticated GSSAPI observations do not establish the selected layer")
		}
	}

	// Install Kerberos SASL wrapping if requested.
	if useSASL {
		// Use type assertion to get the session subkey from the GSSAPI client.
		// The saslKeyProvider interface is intentionally local to avoid
		// coupling the core ldap package to gokrb5 types.
		type saslContextProvider interface {
			SASLContext() (gssapi.SASLSecurityContext, error)
		}
		provider, ok := client.(saslContextProvider)
		if !ok {
			return nil, fmt.Errorf("ldap: GSSAPI client cannot export authenticated SASL sequence and limit state")
		}
		securityContext, err := provider.SASLContext()
		if err != nil {
			return nil, err
		}
		if securityContext.SASLSecurity != int(saslMode) {
			clear(securityContext.KeyValue)
			return nil, fmt.Errorf("ldap: exported SASL context does not match the authenticated layer")
		}
		wrapped, err := newKrbSASLConnWithContext(l.conn, securityContext, saslMode)
		clear(securityContext.KeyValue)
		if err != nil {
			return nil, err
		}
		result.SASLEncryptionType = wrapped.subkey.KeyType
		if saslMode == SASLSecuritySeal {
			result.SASLCipherBits = 128
			if wrapped.subkey.KeyType == 18 || wrapped.subkey.KeyType == 20 {
				result.SASLCipherBits = 256
			}
		}
		l.conn = wrapped
		go l.reader()
	}

	result.ProtectionEstablished = observable && result.Authentication.Complete
	return result, nil
}

func (l *Conn) saslBindTokenExchange(reqControls []Control, reqToken []byte) ([]byte, error) {
	return l.saslBindTokenExchangeWithFlags(reqControls, reqToken, 0)
}

func (l *Conn) saslBindTokenExchangeWithFlags(reqControls []Control, reqToken []byte, flags sendMessageFlags) ([]byte, error) {
	token, _, err := l.saslBindTokenExchangeResult(reqControls, reqToken, flags)
	return token, err
}

func (l *Conn) saslBindTokenExchangeResult(reqControls []Control, reqToken []byte, flags sendMessageFlags) ([]byte, bool, error) {
	// Construct LDAP Bind request with GSSAPI SASL mechanism.
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, l.nextMessageID(), "MessageID"))

	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "User Name"))

	auth := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, "", "authentication")
	auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "GSSAPI", "SASL Mech"))
	if len(reqToken) > 0 {
		auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(reqToken), "Credentials"))
	}
	request.AppendChild(auth)
	envelope.AppendChild(request)
	if len(reqControls) > 0 {
		envelope.AppendChild(encodeControls(reqControls))
	}

	msgCtx, err := l.sendMessageWithFlags(envelope, flags)
	if err != nil {
		return nil, false, err
	}
	defer l.finishMessage(msgCtx)

	packet, err := l.readPacket(msgCtx)
	if err != nil {
		return nil, false, err
	}
	l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if l.Debug {
		if err = addLDAPDescriptions(packet); err != nil {
			return nil, false, err
		}
		ber.PrintPacket(packet)
	}

	// https://www.rfc-editor.org/rfc/rfc4511#section-4.1.1
	// packet is an envelope
	// child 0 is message id
	// child 1 is protocolOp
	if _, err := packetChildCount(packet, 2, 2, "bind response"); err != nil {
		return nil, false, fmt.Errorf("bad bind response")
	}

	protocolOp, err := packetChild(packet, 1)
	if err != nil {
		return nil, false, fmt.Errorf("bad bind response")
	}
RESP:
	switch protocolOp.Description {
	case "Bind Response": // Bind Response
		// Bind Reponse is an LDAP Response (https://www.rfc-editor.org/rfc/rfc4511#section-4.1.9)
		// with an additional optional serverSaslCreds string (https://www.rfc-editor.org/rfc/rfc4511#section-4.2.2)
		// child 0 is resultCode
		resultCode, rcErr := packetChild(protocolOp, 0)
		if rcErr != nil || resultCode.Tag != ber.TagEnumerated {
			break RESP
		}
		code, rcErr := packetInt64(resultCode)
		if rcErr != nil {
			break RESP
		}
		switch code {
		case 14: // Sasl bind in progress
			referral, ok, refErr := packetChildIfPresent(protocolOp, 3)
			if refErr != nil || !ok {
				break RESP
			}
			switch referral.Description {
			case "Referral":
				if referral.ClassType != ber.ClassContext || referral.Tag != ber.TagObjectDescriptor || referral.Data == nil {
					break RESP
				}
				token, readErr := io.ReadAll(referral.Data)
				return token, false, readErr
			}
			// Optional:
			//if len(protocolOp.Children) == 4 {
			//	serverSaslCreds := protocolOp.Children[4]
			//}
		case 0: // Success - Bind OK.
			// SASL layer in effect (if any) (See https://www.rfc-editor.org/rfc/rfc4513#section-5.2.1.4)
			// A negotiated SASL security layer is installed by the caller before restarting the reader.
			return nil, true, nil
		}
	}

	return nil, false, GetLDAPError(packet)
}

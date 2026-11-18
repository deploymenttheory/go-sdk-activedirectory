package ldap

import (
	"math"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// recordTerminalError publishes the first failure once. All waiting operations
// receive that error; a later EOF cannot replace a structural protocol failure.
func (l *Conn) recordTerminalError(err error) {
	l.terminalOnce.Do(func() {
		l.closeErr.Store(err)
		l.setError(err)
	})
}

func (l *Conn) failProtocol(err error) {
	l.recordTerminalError(err)
	// Do not call Conn.Close from processMessages: Close waits for that loop.
	// Closing the socket unblocks reader, which owns the normal shutdown path.
	_ = l.transport().Close()
}

func validateLDAPResponseEnvelope(packet *ber.Packet) (int64, error) {
	children, err := packetChildCount(packet, 2, 3, "LDAP response envelope")
	if err != nil {
		return 0, err
	}
	if packet.ClassType != ber.ClassUniversal || packet.TagType != ber.TypeConstructed || packet.Tag != ber.TagSequence {
		return 0, malformedf("invalid LDAP response envelope tag")
	}
	identifier := children[0]
	if identifier == nil || identifier.ClassType != ber.ClassUniversal || identifier.TagType != ber.TypePrimitive || identifier.Tag != ber.TagInteger {
		return 0, malformedf("invalid LDAP response message identifier")
	}
	messageID, err := packetInt64(identifier)
	if err != nil || messageID <= 0 || messageID > math.MaxInt32 {
		return 0, malformedf("LDAP response message identifier is outside the request range")
	}
	operation := children[1]
	if operation == nil || operation.ClassType != ber.ClassApplication || operation.TagType != ber.TypeConstructed {
		return 0, malformedf("invalid LDAP response operation")
	}
	if len(children) == 3 {
		controls := children[2]
		if controls == nil || controls.ClassType != ber.ClassContext || controls.TagType != ber.TypeConstructed || controls.Tag != 0 {
			return 0, malformedf("invalid LDAP response controls envelope")
		}
		if err := validateLDAPResponseControls(controls); err != nil {
			return 0, err
		}
	}
	if err := validateLDAPResponseMessage(packet); err != nil {
		return 0, err
	}
	return messageID, nil
}

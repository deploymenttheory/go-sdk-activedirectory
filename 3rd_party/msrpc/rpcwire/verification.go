package rpcwire

import "encoding/binary"

// addVerification cryptographically binds the otherwise unauthenticated bind's
// interface/transfer syntax and header-signing declaration to every request.
// Both commands are mandatory; unsupported peers must reject before dispatch.
func addVerification(request []byte, syntax [20]byte) ([]byte, error) {
	if len(request) > maxProtectedStub-63 {
		return nil, ErrPacketTooLong
	}
	offset := (len(request) + 3) &^ 3
	out := make([]byte, offset+60)
	copy(out, request)
	copy(out[offset:], []byte{0x8a, 0xe3, 0x13, 0x71, 0x02, 0xf4, 0x36, 0x71})
	binary.LittleEndian.PutUint16(out[offset+8:], 0x8001)
	binary.LittleEndian.PutUint16(out[offset+10:], 4)
	binary.LittleEndian.PutUint32(out[offset+12:], 1)
	binary.LittleEndian.PutUint16(out[offset+16:], 0xc002)
	binary.LittleEndian.PutUint16(out[offset+18:], 40)
	copy(out[offset+20:], syntax[:])
	transfer := transferSyntax()
	copy(out[offset+40:], transfer[:])
	return out, nil
}

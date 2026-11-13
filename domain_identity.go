package activedirectory

import "encoding/binary"

func validDomainSID(value []byte) bool {
	// Domain SIDs have revision 1, authority 5, and S-1-5-21-X-Y-Z.
	return len(value) == 24 && value[0] == 1 && value[1] == 4 &&
		value[2] == 0 && value[3] == 0 && value[4] == 0 && value[5] == 0 && value[6] == 0 && value[7] == 5 &&
		binary.LittleEndian.Uint32(value[8:12]) == 21
}

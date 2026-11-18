package crypto

// maxRecordBytes bounds plaintext, signed headers and encrypted data before allocation.
const maxRecordBytes = 16 << 20

func sameBuffer(a, b []byte) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}

// validateRecordBuffers requires each sealed buffer to appear exactly once in the
// signing order. This prevents unauthenticated ciphertext and ambiguous aliases.
func validateRecordBuffers(sign, seal [][]byte) error {
	total := 0
	for _, b := range sign {
		if len(b) > maxRecordBytes-total {
			return ErrMessageTooLarge
		}
		total += len(b)
	}
	for i, b := range seal {
		if len(b) == 0 {
			continue
		}
		matches := 0
		for _, signed := range sign {
			if sameBuffer(b, signed) {
				matches++
			}
		}
		if matches != 1 {
			return ErrInvalidToken
		}
		for _, previous := range seal[:i] {
			if sameBuffer(previous, b) {
				return ErrInvalidToken
			}
		}
	}
	return nil
}

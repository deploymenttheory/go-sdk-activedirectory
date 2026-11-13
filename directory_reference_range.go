package activedirectory

import (
	"strconv"
	"strings"
)

// directoryReferenceRange validates a contiguous linked-attribute range while
// preserving the distinction between an omitted attribute and a returned empty set.
func directoryReferenceRange(attrs map[string][][]byte, attribute string, start uint64) (values [][]byte, next uint64, terminal, present bool, err error) {
	attribute = strings.ToLower(attribute)
	var plain [][]byte
	plainFound := false
	var rangeName string
	for name, data := range attrs {
		lower := strings.ToLower(name)
		if lower == attribute {
			if plainFound {
				return nil, 0, false, true, ErrInvalidResult
			}
			plain, plainFound = data, true
		} else if strings.HasPrefix(lower, attribute+";") {
			if rangeName != "" || !strings.HasPrefix(lower, attribute+";range=") {
				return nil, 0, false, true, ErrInvalidResult
			}
			rangeName, values = lower, data
		}
	}
	if rangeName == "" {
		if start != 0 {
			return plain, 0, false, plainFound, ErrIncompleteResult
		}
		return plain, 0, true, plainFound, nil
	}
	if len(plain) != 0 {
		return values, 0, false, true, ErrInvalidResult
	}
	low, high, ok := strings.Cut(strings.TrimPrefix(rangeName, attribute+";range="), "-")
	first, e := strconv.ParseUint(low, 10, 64)
	if !ok || e != nil || first != start {
		return values, 0, false, true, ErrInvalidResult
	}
	if high == "*" {
		return values, 0, true, true, nil
	}
	last, e := strconv.ParseUint(high, 10, 64)
	if e != nil || last < first || last == ^uint64(0) || len(values) == 0 || last-first != uint64(len(values))-1 {
		return values, 0, false, true, ErrInvalidResult
	}
	return values, last + 1, false, true, nil
}

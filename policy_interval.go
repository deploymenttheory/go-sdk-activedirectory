package activedirectory

import (
	"errors"
	"math"
	"strconv"
	"time"
)

var ErrPolicyIntervalRange = errors.New("policy interval cannot be represented without overflow or loss of precision")

// PolicyInterval is a nonnegative count of 100-nanosecond ticks. It preserves
// the full LDAP signed delta-time range, which exceeds time.Duration's range.
// Values through PolicyNever are valid. The LDAP representation is negative.
type PolicyInterval uint64

// PolicyNever represents LDAP's minimum signed 64-bit interval. For maximum
// password age it means no expiry; for lockout duration, manual unlock.
const PolicyNever PolicyInterval = 1 << 63

// PolicyIntervalFromDuration rejects negative or sub-100ns values rather than
// silently rounding them. Use PolicyInterval(ticks) for longer finite values.
func PolicyIntervalFromDuration(duration time.Duration) (PolicyInterval, error) {
	if duration < 0 || duration%100 != 0 {
		return 0, ErrPolicyIntervalRange
	}
	return PolicyInterval(duration / 100), nil
}

// Duration converts a finite representable interval without truncation.
func (i PolicyInterval) Duration() (time.Duration, error) {
	if uint64(i) > uint64(math.MaxInt64/100) {
		return 0, ErrPolicyIntervalRange
	}
	return time.Duration(i) * 100, nil
}

func parsePolicyInterval(text string) (PolicyInterval, error) {
	number, err := strconv.ParseInt(text, 10, 64)
	if err != nil || number > 0 {
		return 0, ErrPolicyIntervalRange
	}
	if number == math.MinInt64 {
		return PolicyNever, nil
	}
	return PolicyInterval(-number), nil
}

func formatPolicyInterval(interval PolicyInterval) string {
	if interval == PolicyNever {
		return "-9223372036854775808"
	}
	return strconv.FormatInt(-int64(interval), 10)
}

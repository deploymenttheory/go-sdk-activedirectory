package activedirectory

import (
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const fileTimeEpochSeconds int64 = 11644473600

// FileTime preserves all 64 bits of the 100ns count since 1601-01-01 UTC,
// including 0, MaxInt64 and all-ones sentinels. Their meaning depends on the
// attribute (for example, accountExpires uses both 0 and MaxInt64 for never).
type FileTime uint64

func ParseFileTime(value string) (FileTime, error) {
	if strings.HasPrefix(value, "-") {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return 0, ErrInvalidValue
		}
		return FileTime(n), nil
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, ErrInvalidValue
	}
	return FileTime(n), nil
}

// LDAPString emits the original 64 bits as a signed LDAP LargeInteger.
func (f FileTime) LDAPString() string { return strconv.FormatInt(int64(f), 10) }
func (f FileTime) Time() (time.Time, error) {
	if f == 0 || f == math.MaxInt64 || f == math.MaxUint64 {
		return time.Time{}, ErrValueSentinel
	}
	if f > math.MaxInt64 {
		return time.Time{}, ErrValueRange
	}
	return time.Unix(int64(f/10000000)-fileTimeEpochSeconds, int64(f%10000000)*100).UTC(), nil
}
func FileTimeFromTime(value time.Time) (FileTime, error) {
	if value.Nanosecond()%100 != 0 {
		return 0, ErrValuePrecision
	}
	seconds := value.Unix()
	if seconds < -fileTimeEpochSeconds || seconds > math.MaxInt64/10000000-fileTimeEpochSeconds {
		return 0, ErrValueRange
	}
	ticks := uint64(seconds+fileTimeEpochSeconds)*10000000 + uint64(value.Nanosecond()/100)
	if ticks > math.MaxInt64 {
		return 0, ErrValueRange
	}
	return FileTime(ticks), nil
}

// Interval100ns preserves a signed LDAP interval without assuming an attribute's
// sign convention. MinInt64 is retained as the common infinite-interval sentinel.
// This is a wire value, distinct from the policy API's nonnegative PolicyInterval.
type Interval100ns int64

func (i Interval100ns) LDAPString() string { return strconv.FormatInt(int64(i), 10) }
func (i Interval100ns) Duration() (time.Duration, error) {
	if i == math.MinInt64 {
		return 0, ErrValueSentinel
	}
	if i > math.MaxInt64/100 || i < math.MinInt64/100 {
		return 0, ErrValueRange
	}
	return time.Duration(i) * 100, nil
}
func Interval100nsFromDuration(value time.Duration) (Interval100ns, error) {
	if value%100 != 0 {
		return 0, ErrValuePrecision
	}
	return Interval100ns(value / 100), nil
}

// GeneralizedTime preserves the exact RFC4517 representation, including time
// zone, hour/minute/second precision, arbitrary fractions and leap seconds.
// Time refuses values Go cannot represent exactly. Input is bounded to 4096 bytes.
type GeneralizedTime struct{ text string }

var generalizedTimeSyntax = regexp.MustCompile(`^([0-9]{10})([0-9]{2})?([0-9]{2})?([.,][0-9]+)?(Z|[+-][0-9]{2}(?:[0-9]{2})?)$`)

func ParseGeneralizedTime(value string) (GeneralizedTime, error) {
	if _, _, _, _, err := generalizedParts(value); err != nil {
		return GeneralizedTime{}, err
	}
	return GeneralizedTime{text: value}, nil
}
func (g GeneralizedTime) String() string { return g.text }
func (g GeneralizedTime) Time() (time.Time, error) {
	base, fraction, unit, leap, err := generalizedParts(g.text)
	if err != nil {
		return time.Time{}, err
	}
	if leap {
		return time.Time{}, ErrValuePrecision
	}
	if fraction == "" {
		return base, nil
	}
	numerator, ok := new(big.Int).SetString(fraction, 10)
	if !ok {
		return time.Time{}, ErrInvalidValue
	}
	numerator.Mul(numerator, big.NewInt(int64(unit)))
	denominator := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(len(fraction))), nil)
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(numerator, denominator, remainder)
	if remainder.Sign() != 0 {
		return time.Time{}, ErrValuePrecision
	}
	return base.Add(time.Duration(quotient.Int64())), nil
}

func generalizedParts(value string) (time.Time, string, time.Duration, bool, error) {
	if len(value) > 4096 {
		return time.Time{}, "", 0, false, ErrInvalidValue
	}
	parts := generalizedTimeSyntax.FindStringSubmatch(value)
	if parts == nil {
		return time.Time{}, "", 0, false, ErrInvalidValue
	}
	stamp, unit := parts[1], time.Hour
	if parts[2] != "" {
		stamp += parts[2]
		unit = time.Minute
	} else {
		stamp += "00"
	}
	leap := parts[3] == "60"
	if parts[3] != "" && !leap {
		stamp += parts[3]
		unit = time.Second
	} else {
		stamp += "00"
	}
	if leap {
		unit = time.Second
	}
	zone := parts[5]
	if zone == "Z" {
		zone = "+0000"
	} else if len(zone) == 3 {
		zone += "00"
	}
	// time.Parse accepts offset 24:00 and minute 60; LDAP permits neither.
	if zone[1:3] > "23" || zone[3:5] > "59" {
		return time.Time{}, "", 0, false, ErrInvalidValue
	}
	base, err := time.Parse("20060102150405-0700", stamp+zone)
	if err != nil {
		return time.Time{}, "", 0, false, ErrInvalidValue
	}
	fraction := strings.TrimLeft(parts[4], ".,")
	return base.UTC(), fraction, unit, leap, nil
}

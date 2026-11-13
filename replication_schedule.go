package activedirectory

import (
	"encoding/binary"
	"errors"
	"time"
)

var ErrInvalidReplicationSchedule = errors.New("invalid replication schedule")

// ReplicationSchedule is a UTC week, Sunday first, with four 15-minute slots
// per hour. Zero means no slots enabled. It never applies local timezone/DST.
type ReplicationSchedule [7][24][4]bool

func (s *ReplicationSchedule) Set(day time.Weekday, hour, quarter int, enabled bool) error {
	if s == nil || day < time.Sunday || day > time.Saturday || hour < 0 || hour > 23 || quarter < 0 || quarter > 3 {
		return ErrInvalidReplicationSchedule
	}
	s[day][hour][quarter] = enabled
	return nil
}

// Bytes encodes the documented 188-byte single-interval SCHEDULE. The quarter
// order follows Windows ActiveDirectorySchedule.GetUnmanagedSchedule (1,2,4,8).
func (s ReplicationSchedule) Bytes() []byte {
	data := make([]byte, 188)
	binary.LittleEndian.PutUint32(data, 188)
	binary.LittleEndian.PutUint32(data[8:], 1)
	binary.LittleEndian.PutUint32(data[16:], 20)
	for day := range 7 {
		for hour := range 24 {
			for quarter := range 4 {
				if s[day][hour][quarter] {
					data[20+day*24+hour] |= 1 << quarter
				}
			}
		}
	}
	return data
}

// ReplicationScheduleFromBytes rejects malformed/unsupported headers and
// reserved bits. Callers retain the original raw attribute alongside failures.
func ReplicationScheduleFromBytes(data []byte) (ReplicationSchedule, error) {
	var schedule ReplicationSchedule
	if len(data) != 188 || binary.LittleEndian.Uint32(data) != 188 || binary.LittleEndian.Uint32(data[4:]) != 0 || binary.LittleEndian.Uint32(data[8:]) != 1 || binary.LittleEndian.Uint32(data[12:]) != 0 || binary.LittleEndian.Uint32(data[16:]) != 20 {
		return schedule, ErrInvalidReplicationSchedule
	}
	for day := range 7 {
		for hour := range 24 {
			value := data[20+day*24+hour]
			if value&0xf0 != 0 {
				return schedule, ErrInvalidReplicationSchedule
			}
			for quarter := range 4 {
				schedule[day][hour][quarter] = value&(1<<quarter) != 0
			}
		}
	}
	return schedule, nil
}

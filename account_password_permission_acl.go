package activedirectory

import (
	"encoding/binary"
	"slices"
)

const passwordChangeControlAccess uint32 = 0x100

var passwordChangeGUID = func() GUID { guid, _ := ParseGUID("ab721a53-1e2f-11d0-9819-00aa0040529b"); return guid }()
var passwordChangeSIDs = [][]byte{
	{1, 1, 0, 0, 0, 0, 0, 5, 10, 0, 0, 0}, // S-1-5-10, SELF
	{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0},  // S-1-1-0, Everyone
}

// PasswordChangeACEObservation reports a recognized ACE pattern, not the
// outcome of an access check for an arbitrary logon token or a password change.
type PasswordChangeACEObservation struct {
	ExplicitAllow, ExplicitDeny   bool
	InheritedAllow, InheritedDeny bool
}

type passwordChangeACE struct {
	principal int
	deny      bool
	inherited bool
	mask      uint32
	canonical bool
}

// A matching ACE must name the extended right and a well-known SID directly.
// Inheritance restrictions and callbacks are not simplified into ordinary ACEs.
func decodePasswordChangeACE(ace []byte) (passwordChangeACE, bool) {
	result := passwordChangeACE{principal: -1}
	if len(ace) < 28 || (ace[0] != 5 && ace[0] != 6 && ace[0] != 11 && ace[0] != 12) {
		return result, false
	}
	flags := binary.LittleEndian.Uint32(ace[8:12])
	if flags&1 == 0 || !slices.Equal(ace[12:28], passwordChangeGUID.Bytes()) {
		return result, false
	}
	offset := 28
	if flags&2 != 0 {
		offset += 16
	}
	if offset+8 > len(ace) {
		return result, false
	}
	length := 8 + 4*int(ace[offset+1])
	if offset+length > len(ace) {
		return result, false
	}
	for i, sid := range passwordChangeSIDs {
		if slices.Equal(ace[offset:offset+length], sid) {
			result.principal = i
		}
	}
	if result.principal < 0 {
		return result, false
	}
	result.deny = ace[0] == 6 || ace[0] == 12
	result.inherited = ace[1]&0x10 != 0
	result.mask = binary.LittleEndian.Uint32(ace[4:8])
	result.canonical = (ace[0] == 5 || ace[0] == 6) && flags == 1 && ace[1]&^byte(0x10) == 0 && offset+length == len(ace)
	return result, true
}

func observePasswordChangeACL(acl directoryDACL) (self, everyone PasswordChangeACEObservation, cannot *bool, unknown bool) {
	states := []*PasswordChangeACEObservation{&self, &everyone}
	for _, ace := range acl.aces {
		entry, matches := decodePasswordChangeACE(ace)
		if !matches {
			if ace[0] > 21 {
				unknown = true
			}
			continue
		}
		if !entry.canonical || entry.mask&passwordChangeControlAccess == 0 {
			unknown = true
			continue
		}
		state := states[entry.principal]
		switch {
		case entry.inherited && entry.deny:
			state.InheritedDeny = true
		case entry.inherited:
			state.InheritedAllow = true
		case entry.deny:
			state.ExplicitDeny = true
		default:
			state.ExplicitAllow = true
		}
	}
	if !unknown {
		value := self.ExplicitDeny || self.InheritedDeny || everyone.ExplicitDeny || everyone.InheritedDeny
		cannot = &value
	}
	return
}

func passwordChangeRule(principal int, deny bool) []byte {
	ace := make([]byte, 40)
	ace[0] = 5
	if deny {
		ace[0] = 6
	}
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
	binary.LittleEndian.PutUint32(ace[4:8], passwordChangeControlAccess)
	binary.LittleEndian.PutUint32(ace[8:12], 1)
	copy(ace[12:28], passwordChangeGUID.Bytes())
	copy(ace[28:], passwordChangeSIDs[principal])
	return ace
}

// Only the CONTROL_ACCESS bit of explicit, unqualified matching ACEs is
// changed. Other bits remain in their original allow/deny ACE; inherited and
// unknown forms remain byte-for-byte intact. New rules are inserted in the
// explicit deny/allow portion without reordering existing unrelated rules.
func changePasswordPermissionACEs(acl directoryDACL, cannot bool) ([][]byte, bool, error) {
	_, _, _, unknown := observePasswordChangeACL(acl)
	if unknown {
		return nil, false, ErrAccountPasswordPermission
	}
	aces := make([][]byte, 0, len(acl.aces)+2)
	var have [2]bool
	changed := false
	for _, ace := range acl.aces {
		entry, matches := decodePasswordChangeACE(ace)
		if !matches || entry.inherited || !entry.canonical || entry.mask&passwordChangeControlAccess == 0 {
			aces = append(aces, ace)
			continue
		}
		if entry.deny == cannot {
			have[entry.principal] = true
			aces = append(aces, ace)
			continue
		}
		changed = true
		if remaining := entry.mask &^ passwordChangeControlAccess; remaining != 0 {
			preserved := slices.Clone(ace)
			binary.LittleEndian.PutUint32(preserved[4:8], remaining)
			aces = append(aces, preserved)
		}
	}
	var added [][]byte
	for i, present := range have {
		if !present {
			added = append(added, passwordChangeRule(i, cannot))
			changed = true
		}
	}
	if len(added) != 0 {
		at := 0
		if !cannot {
			// Place new explicit allow rules after all explicit denies and before
			// inherited rules. Existing unknown/noncanonical order is preserved.
			for at < len(aces) && aces[at][1]&0x10 == 0 {
				at++
			}
		}
		aces = slices.Insert(aces, at, added...)
	}
	return aces, changed, nil
}

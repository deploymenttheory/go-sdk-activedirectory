package drsrwire

import (
	"context"
	"errors"
)

// DecodeReplicationInfo accepts a complete authenticated response stub. RPC faults
// and truncated protected streams must be handled separately, before this decoder.
func DecodeReplicationInfo(ctx context.Context, requested uint32, stub []byte) (reply Reply, err error) {
	if requested != 0 && requested != 3 && requested != 4 && requested != 5 {
		return reply, ErrMalformedNDR
	}
	if len(stub) > maxStubBytes {
		return reply, ErrNDRLimit
	}
	c := &cursor{ctx: ctx, data: stub}
	reply.Kind = c.u32()
	discriminant := c.u32()
	reply.Present = c.u32() != 0
	if c.err != nil {
		return reply, c.err
	}
	if discriminant != reply.Kind || reply.Kind != 0 && reply.Kind != 3 && reply.Kind != 4 && reply.Kind != 5 {
		return reply, ErrMalformedNDR
	}
	var semantic error
	if reply.Present {
		conformance := c.u32()
		minimum := 36
		switch reply.Kind {
		case 0:
			c.take(0, 8)
			reply.Count = c.u32()
			c.u32()
			minimum = 128
		case 3, 4:
			reply.Count = c.u32()
			c.u32()
		case 5:
			reply.Started = c.filetime()
			reply.Count = c.u32()
			minimum = 68
		}
		if c.err != nil {
			return reply, c.err
		}
		if conformance > maxRecords || reply.Count > maxRecords {
			return reply, ErrNDRLimit
		}
		if conformance != reply.Count {
			semantic = ErrMalformedNDR
		}
		if int(conformance) > (len(stub)-c.offset)/minimum {
			return reply, ErrMalformedNDR
		}
		switch reply.Kind {
		case 0:
			reply.Neighbors = readNeighbors(c, int(conformance))
		case 3, 4:
			reply.Failures = readFailures(c, int(conformance))
		case 5:
			reply.Operations = readOperations(c, int(conformance))
		}
		if c.err != nil {
			return reply, errors.Join(semantic, c.err)
		}
	}
	status := c.u32()
	if c.err != nil {
		return reply, errors.Join(semantic, c.err)
	}
	if c.offset != len(stub) {
		return reply, errors.Join(semantic, ErrMalformedNDR)
	}
	reply.Status = status
	if reply.Status != 0 {
		return Reply{Kind: reply.Kind, Status: reply.Status}, semantic
	}
	if reply.Kind != requested || !reply.Present {
		semantic = errors.Join(semantic, ErrMalformedNDR)
	}
	return reply, semantic
}

func readNeighbors(c *cursor, count int) []Neighbor {
	rows := make([]Neighbor, count)
	references := make([][4]uint32, count)
	for i := range rows {
		c.take(0, 8)
		for j := range references[i] {
			references[i][j] = c.u32()
		}
		r := &rows[i]
		r.ReplicaFlags = c.u32()
		c.u32()
		r.PartitionGUID, r.PartnerGUID, r.InvocationID, r.TransportGUID = c.guid(), c.guid(), c.guid(), c.guid()
		r.LastObjectUSN, r.AttributeFilterUSN = c.signed64(), c.signed64()
		r.LastSuccess, r.LastAttempt = c.filetime(), c.filetime()
		r.LastResult, r.ConsecutiveFailures = c.u32(), c.u32()
		if c.err != nil {
			return nil
		}
	}
	for i := range rows {
		r, ref := &rows[i], references[i]
		r.PartitionDN, r.PartnerDN, r.PartnerAddress, r.TransportDN = c.text(ref[0]), c.text(ref[1]), c.text(ref[2]), c.text(ref[3])
		if c.err != nil {
			return rows[:i]
		}
	}
	return rows
}

func readFailures(c *cursor, count int) []Failure {
	rows := make([]Failure, count)
	references := make([]uint32, count)
	for i := range rows {
		r := &rows[i]
		references[i] = c.u32()
		r.PartnerGUID = c.guid()
		r.Time = c.filetime()
		r.FailureCount, r.LastResult = c.u32(), c.u32()
		if c.err != nil {
			return nil
		}
	}
	for i := range rows {
		rows[i].PartnerDN = c.text(references[i])
		if c.err != nil {
			return rows[:i]
		}
	}
	return rows
}

func readOperations(c *cursor, count int) []Operation {
	rows := make([]Operation, count)
	references := make([][3]uint32, count)
	for i := range rows {
		r := &rows[i]
		r.Enqueued = c.filetime()
		r.SerialNumber, r.Priority = c.u32(), c.u32()
		r.Type = uint32(c.u16())
		r.Options = c.u32()
		for j := range references[i] {
			references[i][j] = c.u32()
		}
		r.PartitionGUID, r.PartnerGUID = c.guid(), c.guid()
		if c.err != nil {
			return nil
		}
	}
	for i := range rows {
		r, ref := &rows[i], references[i]
		r.PartitionDN, r.PartnerDN, r.PartnerAddress = c.text(ref[0]), c.text(ref[1]), c.text(ref[2])
		if c.err != nil {
			return rows[:i]
		}
	}
	return rows
}

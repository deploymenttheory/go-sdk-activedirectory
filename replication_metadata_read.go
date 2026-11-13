package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

const (
	metadataAttribute       = "msds-replattributemetadata"
	metadataLink            = "msds-replvaluemetadata"
	metadataVector          = "msds-ncreplcursors"
	metadataShowDeleted     = "1.2.840.113556.1.4.417"
	metadataShowDeactivated = "1.2.840.113556.1.4.2065"
)

func metadataProperty(name string) bool {
	return name != "1.1" && attributeDescription.MatchString(name) && !strings.Contains(name, ";")
}

func (q ReplicationAttributeMetadataQuery) validate() error {
	if err := q.Selection.validate(); err != nil {
		return err
	}
	if q.ObjectDN == "" || !validDirectoryText(q.ObjectDN) || q.IncludeDeactivatedLinks && !q.IncludeLinkedValues {
		return ErrInvalidReplicationQuery
	}
	for _, name := range q.Properties {
		if name == "*" && len(q.Properties) == 1 {
			continue
		}
		if !metadataProperty(name) {
			return ErrInvalidProperty
		}
	}
	return nil
}

func (q ReplicationAttributeMetadataQuery) selected(name string) bool {
	return len(q.Properties) == 0 || slices.Contains(q.Properties, "*") || slices.ContainsFunc(q.Properties, func(property string) bool { return strings.EqualFold(name, property) })
}

// ReadReplicationAttributeMetadata reads documented LDAP constructed metadata
// over the configured transport. Scoped selection uses ResolveReplicationTargets.
// Failed targets remain in Servers; missing/hidden metadata is incomplete.
func ReadReplicationAttributeMetadata(ctx context.Context, config Config, query ReplicationAttributeMetadataQuery) (ReplicationAttributeMetadataResult, error) {
	return readReplicationAttributeMetadata(ctx, config, query, Dial)
}

func readReplicationAttributeMetadata(ctx context.Context, config Config, query ReplicationAttributeMetadataQuery, dial func(context.Context, Config) (*Client, error)) (result ReplicationAttributeMetadataResult, err error) {
	if err = query.validate(); err != nil {
		return result, err
	}
	config, err = config.normalized()
	if err != nil {
		return result, err
	}
	result.Targets, err = resolveReplicationTargets(ctx, config, query.Selection, dial)
	for _, endpoint := range result.Targets.Servers {
		server := ReplicationAttributeMetadataServer{ObjectDN: query.ObjectDN}
		serverConfig := config
		serverConfig.Endpoint = endpoint
		server.Observation = metadataReadServer(ctx, serverConfig, dial, func(ctx context.Context, client *Client, root RootDSE) error {
			var controls []string
			if query.IncludeDeletedObjects {
				controls = append(controls, metadataShowDeleted)
			}
			if query.IncludeDeactivatedLinks {
				controls = append(controls, metadataShowDeactivated)
			}
			for _, control := range controls {
				if !slices.Contains(root.SupportedControls, control) {
					return fmt.Errorf("%w: metadata control %s was not advertised", ErrUnsupportedDirectory, control)
				}
			}
			var attributeErr, linkErr error
			objects, state := readMetadataValues(ctx, client, query.ObjectDN, metadataAttribute, controls, func(value []byte) error {
				row, decodeErr := decodeMetadataAttribute(value)
				if decodeErr == nil && query.selected(row.AttributeName) {
					server.Attributes = append(server.Attributes, row)
				}
				return decodeErr
			})
			server.Objects = append(server.Objects, objects...)
			server.AttributesState = state
			attributeErr = state.Error
			if query.IncludeLinkedValues {
				objects, state = readMetadataValues(ctx, client, query.ObjectDN, metadataLink, controls, func(value []byte) error {
					row, decodeErr := decodeMetadataLink(value)
					if decodeErr == nil && query.selected(row.AttributeName) {
						server.LinkedValues = append(server.LinkedValues, row)
					}
					return decodeErr
				})
				server.Objects = append(server.Objects, objects...)
				server.LinkedValuesState = state
				linkErr = state.Error
			}
			return errors.Join(attributeErr, linkErr)
		})
		if !server.AttributesState.Requested {
			server.AttributesState = replicationState(server.Observation.Error)
		}
		if query.IncludeLinkedValues && !server.LinkedValuesState.Requested {
			server.LinkedValuesState = replicationState(server.Observation.Error)
		}
		result.Servers = append(result.Servers, server)
		err = errors.Join(err, server.Observation.Error)
	}
	result.Complete = err == nil && result.Targets.Complete
	return result, err
}

// ReadReplicationUpToDatenessVectors reads each selected server/partition and
// retains individual partition failures. No replication or directory write is
// triggered. A watermark belongs to an invocation ID, not merely a server name.
func ReadReplicationUpToDatenessVectors(ctx context.Context, config Config, query ReplicationVectorQuery) (ReplicationVectorsResult, error) {
	return readReplicationVectors(ctx, config, query, Dial)
}

func readReplicationVectors(ctx context.Context, config Config, query ReplicationVectorQuery, dial func(context.Context, Config) (*Client, error)) (result ReplicationVectorsResult, err error) {
	if err = query.Selection.validate(); err != nil {
		return result, err
	}
	for _, partition := range query.PartitionDNs {
		if partition == "" || !validDirectoryText(partition) {
			return result, ErrInvalidReplicationQuery
		}
	}
	config, err = config.normalized()
	if err != nil {
		return result, err
	}
	result.Targets, err = resolveReplicationTargets(ctx, config, query.Selection, dial)
	for _, endpoint := range result.Targets.Servers {
		server := ReplicationVectorServer{}
		serverConfig := config
		serverConfig.Endpoint = endpoint
		server.Observation = metadataReadServer(ctx, serverConfig, dial, func(ctx context.Context, client *Client, root RootDSE) error {
			partitions := query.PartitionDNs
			if len(partitions) == 0 {
				partitions = root.NamingContexts
			}
			if len(partitions) == 0 {
				return fmt.Errorf("%w: namingContexts was omitted", ErrIncompleteResult)
			}
			var combined error
			for _, partition := range partitions {
				entry := ReplicationVectorPartition{PartitionDN: partition}
				entry.Objects, entry.State = readMetadataValues(ctx, client, partition, metadataVector, nil, func(value []byte) error {
					row, decodeErr := decodeMetadataCursor(value)
					if decodeErr == nil {
						entry.Cursors = append(entry.Cursors, row)
					}
					return decodeErr
				})
				server.Partitions = append(server.Partitions, entry)
				combined = errors.Join(combined, entry.State.Error)
			}
			return combined
		})
		if len(server.Partitions) == 0 {
			for _, partition := range query.PartitionDNs {
				server.Partitions = append(server.Partitions, ReplicationVectorPartition{PartitionDN: partition, State: replicationState(server.Observation.Error)})
			}
		}
		result.Servers = append(result.Servers, server)
		err = errors.Join(err, server.Observation.Error)
	}
	result.Complete = err == nil && result.Targets.Complete
	return result, err
}

func metadataReadServer(ctx context.Context, config Config, dial func(context.Context, Config) (*Client, error), read func(context.Context, *Client, RootDSE) error) (observation ReplicationServerObservation) {
	observation.Endpoint = config.Endpoint
	ctx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	var err error
	defer func() {
		err = errors.Join(err, context.Cause(ctx))
		observation.Complete = err == nil
		if err != nil {
			observation.Error = &ReplicationReadError{Operation: "read replication metadata", Server: config.Endpoint, Cause: err}
		}
	}()
	if err = context.Cause(ctx); err != nil {
		return observation
	}
	client, dialErr := dial(ctx, config)
	err = dialErr
	if err != nil {
		return observation
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	observation.RootDSE, err = client.RootDSE(ctx, RootDSEOptions{})
	if err != nil {
		return observation
	}
	if observation.RootDSE.Capabilities().Type == DirectoryUnknown {
		err = ErrUnsupportedDirectory
		return observation
	}
	err = read(ctx, client, observation.RootDSE)
	return observation
}

type metadataControlledSession interface {
	metadataBaseObject(context.Context, string, []string, []string) (map[string][][]byte, error)
}

func readMetadataValues(ctx context.Context, client *Client, base, attribute string, controls []string, consume func([]byte) error) (objects []Object, state ReplicationQueryState) {
	state.Requested = true
	err := client.read(ctx, func(bounded context.Context) error {
		var start uint64
		var firstUSN string
		for {
			if err := context.Cause(bounded); err != nil {
				return err
			}
			requested := attribute + ";binary"
			if start != 0 {
				requested = fmt.Sprintf("%s;range=%d-*", requested, start)
			}
			properties := []string{requested, "uSNChanged"}
			var attrs map[string][][]byte
			var readErr error
			if len(controls) == 0 {
				attrs, readErr = client.session.rangedBaseObject(bounded, base, properties)
			} else if session, ok := client.session.(metadataControlledSession); ok {
				attrs, readErr = session.metadataBaseObject(bounded, base, properties, controls)
			} else {
				return ErrUnsupported
			}
			objects = append(objects, Object{DistinguishedName: base, Attributes: attrs, RequestedProperties: properties})
			values, next, terminal, rangeErr := metadataRange(attrs, attribute, start)
			var decodeErr error
			for _, value := range values {
				rowErr := consume(value)
				if rowErr == nil {
					state.Available = true
				}
				decodeErr = errors.Join(decodeErr, rowErr)
			}
			combined := errors.Join(readErr, rangeErr, decodeErr)
			if !terminal || start != 0 {
				usns := attrs["usnchanged"]
				if len(usns) != 1 {
					combined = errors.Join(combined, fmt.Errorf("%w: missing range consistency USN", ErrIncompleteResult))
				} else {
					current := string(usns[0])
					_, parseErr := strconv.ParseUint(current, 10, 64)
					if parseErr != nil {
						combined = errors.Join(combined, ErrInvalidResult)
					} else if start == 0 {
						firstUSN = current
					} else if current != firstUSN {
						combined = errors.Join(combined, fmt.Errorf("%w: object changed during ranged metadata read", ErrIncompleteResult))
					}
				}
			}
			if combined != nil || terminal {
				return combined
			}
			if next > 1<<20 {
				return fmt.Errorf("%w: metadata range exceeds safety bound", ErrIncompleteResult)
			}
			start = next
		}
	})
	state.Error = err
	state.Complete = err == nil
	return objects, state
}

func metadataRange(attrs map[string][][]byte, attribute string, start uint64) (values [][]byte, next uint64, terminal bool, err error) {
	found := false
	for name, rows := range attrs {
		parts := strings.Split(strings.ToLower(name), ";")
		if parts[0] != attribute {
			continue
		}
		if found {
			return nil, 0, false, ErrInvalidResult
		}
		found = true
		binaryOption := false
		rangeOption := ""
		for _, option := range parts[1:] {
			if option == "binary" && !binaryOption {
				binaryOption = true
			} else if strings.HasPrefix(option, "range=") && rangeOption == "" {
				rangeOption = strings.TrimPrefix(option, "range=")
			} else {
				return nil, 0, false, ErrInvalidResult
			}
		}
		if !binaryOption {
			return nil, 0, false, ErrInvalidResult
		}
		values = rows
		if rangeOption == "" {
			if start != 0 {
				return nil, 0, false, ErrIncompleteResult
			}
			terminal = true
			continue
		}
		low, high, ok := strings.Cut(rangeOption, "-")
		if !ok {
			return nil, 0, false, ErrInvalidResult
		}
		first, parseErr := strconv.ParseUint(low, 10, 32)
		if parseErr != nil || first != start {
			return nil, 0, false, ErrIncompleteResult
		}
		if high == "*" {
			terminal = true
			continue
		}
		last, parseErr := strconv.ParseUint(high, 10, 32)
		if parseErr != nil || last < first || last-first+1 != uint64(len(rows)) {
			return values, 0, false, ErrIncompleteResult
		}
		next = last + 1
	}
	if !found || len(values) == 0 {
		return values, 0, false, fmt.Errorf("%w: metadata omitted; empty, denied and unavailable cannot be distinguished", ErrIncompleteResult)
	}
	return values, next, terminal, nil
}

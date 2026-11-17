package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// DirectoryService reads topology through the client's authenticated endpoint.
// It never discovers another endpoint, rebinds, or retains credentials.
type DirectoryService struct{ client *Client }

func (c *Client) Directory() *DirectoryService { return &DirectoryService{client: c} }

type InternalDirectoryRead struct {
	InternalClient      *Client
	InternalCtx         context.Context
	InternalCancel      context.CancelFunc
	InternalOperation   string
	InternalObservation admodel.DirectoryObservation
	InternalErr         error
	InternalReady       bool
	InternalCategories  map[string]*bool
}

func InternalDirectoryServiceBegin(d *DirectoryService,
	ctx context.Context,
	operation string,
	requireADDS bool,
) (*InternalDirectoryRead, error) {
	if d == nil || d.client == nil || d.client.session == nil {
		return nil, admodel.ErrClosed
	}
	// This deadline includes every public read and each wait for the client gate.
	// No gate is held here: RootDSE and Search acquire/release it themselves.
	bounded, cancel := context.WithTimeout(ctx, d.client.config.Timeout)
	r := &InternalDirectoryRead{
		InternalClient:     d.client,
		InternalCtx:        bounded,
		InternalCancel:     cancel,
		InternalOperation:  operation,
		InternalCategories: make(map[string]*bool),
	}
	r.InternalObservation.Source = d.client.config.Endpoint
	r.InternalObservation.Complete = true
	var err error
	r.InternalObservation.RootDSE, err = d.client.RootDSE(bounded, admodel.RootDSEOptions{})
	r.InternalAdd(err)
	if err == nil && requireADDS {
		r.InternalAdd(r.InternalObservation.RootDSE.Capabilities().RequireADDS(operation))
	}
	r.InternalReady = r.InternalErr == nil
	return r, nil
}

func (r *InternalDirectoryRead) InternalAdd(err error) {
	if err != nil {
		r.InternalErr = errors.Join(r.InternalErr, err)
		r.InternalObservation.Complete = false
	}
}

func (r *InternalDirectoryRead) InternalFinish(observation *admodel.DirectoryObservation) error {
	r.InternalAdd(context.Cause(r.InternalCtx))
	if context.Cause(r.InternalClient.lifetime) != nil {
		r.InternalAdd(admodel.ErrClosed)
	}
	r.InternalCancel()
	*observation = r.InternalObservation
	if r.InternalErr != nil {
		return &admodel.DirectoryReadError{Operation: r.InternalOperation, Cause: r.InternalErr}
	}
	return nil
}

func (r *InternalDirectoryRead) InternalSearch(options admodel.SearchOptions) admodel.SearchResult {
	if err := context.Cause(r.InternalCtx); err != nil {
		r.InternalAdd(err)
		return admodel.SearchResult{}
	}
	result, err := r.InternalClient.Search(r.InternalCtx, options)
	r.InternalObservation.Objects = append(r.InternalObservation.Objects, result.Objects...)
	if !result.Complete {
		r.InternalObservation.Complete = false
		if !result.LimitReached && err == nil {
			r.InternalAdd(admodel.ErrIncompleteResult)
		}
	}
	for _, object := range result.Objects {
		if object.DistinguishedName == "" {
			r.InternalAdd(admodel.ErrInvalidResult)
		}
		for name := range object.Attributes {
			if strings.Contains(name, ";range=") {
				r.InternalAdd(admodel.ErrIncompleteResult)
			}
		}
	}
	r.InternalAdd(err)
	return result
}

func (r *InternalDirectoryRead) InternalOne(
	base, filter string,
	properties []string,
) admodel.Object {
	if base == "" {
		r.InternalAdd(
			fmt.Errorf("%w: missing base DN for linked read", admodel.ErrIncompleteResult),
		)
		return admodel.Object{}
	}
	result := r.InternalSearch(
		admodel.SearchOptions{
			Base:       base,
			Scope:      admodel.ScopeBase,
			Filter:     filter,
			Properties: properties,
		},
	)
	if len(result.Objects) == 1 {
		return result.Objects[0]
	}
	if len(result.Objects) > 1 {
		r.InternalAdd(
			fmt.Errorf("%w: base read returned multiple objects", admodel.ErrInvalidResult),
		)
	} else if result.Complete {
		r.InternalAdd(admodel.ErrDirectoryObjectNotFound)
	}
	return admodel.Object{}
}

func (r *InternalDirectoryRead) InternalRequire(value *string, attribute string) string {
	if value == nil || *value == "" {
		r.InternalAdd(
			fmt.Errorf(
				"%w: required attribute %s was not returned",
				admodel.ErrIncompleteResult,
				attribute,
			),
		)
		return ""
	}
	return *value
}

func (r *InternalDirectoryRead) InternalSelectedDomain(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if r.InternalClient.config.Partition != "" {
		return r.InternalClient.config.Partition
	}
	return r.InternalRequire(
		r.InternalObservation.RootDSE.DefaultNamingContext,
		"defaultNamingContext",
	)
}

func (r *InternalDirectoryRead) InternalParent(dn string) string {
	parent, err := admodel.InternalParentDirectoryDN(dn)
	r.InternalAdd(err)
	return parent
}

func (r *InternalDirectoryRead) InternalContainer(containers map[string]string, key string) string {
	value := containers[key]
	if value == "" {
		r.InternalAdd(
			fmt.Errorf(
				"%w: required well-known container was not returned",
				admodel.ErrIncompleteResult,
			),
		)
	}
	return value
}

package directory_settings

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// OptionalFeatures reads the configuration's Optional Features container on
// this authenticated endpoint. Backlink ranges continue on this connection.
// A complete read does not establish that every attribute was visible.
func (c *Service) OptionalFeatures(
	ctx context.Context,
	query OptionalFeatureQuery,
) (OptionalFeaturesResult, error) {
	var result admodel.OptionalFeaturesResult
	if err := query.Validate(); err != nil {
		return result, err
	}
	err := adengine.InternalClientRead(c.engine(), ctx, func(bounded context.Context) error {
		root, err := admodel.InternalOptionalFeatureRoot(
			bounded,
			adengine.InternalClientSession(c.engine()),
		)
		result.Observation.Source = adengine.InternalClientConfig(c.engine()).Endpoint
		result.Observation.RootDSE = root
		if err != nil {
			return err
		}
		search, searchErr := admodel.InternalOptionalFeatureSearch(
			bounded,
			adengine.InternalClientSession(c.engine()),
			root,
			query,
		)
		err = searchErr
		result.LimitReached = search.LimitReached
		result.Observation.Objects = search.Objects
		for _, object := range search.Objects {
			feature, decodeErr := admodel.InternalDecodeOptionalFeature(object)
			if searchErr == nil && decodeErr == nil {
				decodeErr = admodel.InternalReadOptionalFeatureScopes(
					bounded,
					adengine.InternalClientSession(c.engine()),
					&feature,
				)
				result.Observation.Objects = append(
					result.Observation.Objects,
					feature.EnabledScopeObjects...)
			}
			result.Features = append(result.Features, feature)
			err = errors.Join(err, decodeErr)
		}
		result.Complete = search.Complete && err == nil
		return err
	})
	result.Complete = result.Complete && err == nil
	result.Observation.Complete = result.Complete
	return result, err
}

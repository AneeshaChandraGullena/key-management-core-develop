// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package endpoints

import (
	"fmt"

	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/definitions"
	corecomms "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"

	"context"

	"github.com/go-kit/kit/endpoint"
)

// MakePostEndpoint generates a RESTful Endpoint for secret creation.
// If multiple secrets are specified, multiple PostSecret calls are invoked.
// It returns a collection with data only if include_resouce is part of the request.
// Errors are handled in the response so that it doesn't interfere with Circuit Breaker calculations
func MakePostEndpoint(svc definitions.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		if req, ok := request.(*communications.SecretRequest); ok {
			return svc.Post(ctx, req)
		}
		return nil, fmt.Errorf("Requires type *communications.SecretRequest, received %T", request)
	}
}

// MakeActionsEndpoint generates an Endpoint for actions by a secrets using the post methods
func MakeActionsEndpoint(svc definitions.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		if req, ok := request.(*corecomms.SecretActionRequest); ok {
			return svc.Actions(ctx, req)
		}
		return nil, fmt.Errorf("Requires type *corecomms.SecretActionRequest, received %T", request)
	}
}

// MakeGetEndpoint generates an Endpoint for secret retrieval
func MakeGetEndpoint(svc definitions.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		if req, ok := request.(*communications.IDRequest); ok {
			return svc.Get(ctx, req)
		}
		return nil, fmt.Errorf("Requires type *communications.IDRequest, received %T", request)
	}
}

// MakeListEndpoint generates an Endpoint for secret retrieval
func MakeListEndpoint(svc definitions.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		if req, ok := request.(*communications.BaseRequest); ok {
			return svc.List(ctx, req)
		}
		return nil, fmt.Errorf("Requires type *communications.BaseRequest, received %T", request)
	}
}

// MakeHeadEndpoint generates an Endpoint for secret metadata retrieval
func MakeHeadEndpoint(svc definitions.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		if req, ok := request.(*communications.BaseRequest); ok {
			return svc.Head(ctx, req)
		}
		return nil, fmt.Errorf("Requires type *communications.BaseRequest, received %T", request)
	}
}

// MakeDeleteEndpoint generates an Endpoint for secret retrieval
func MakeDeleteEndpoint(svc definitions.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		if req, ok := request.(*communications.IDRequest); ok {
			return svc.Delete(ctx, req)
		}
		return nil, fmt.Errorf("Requires type *communications.IDRequest, received %T", request)
	}
}

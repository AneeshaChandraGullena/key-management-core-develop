// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package endpoints

import "github.com/go-kit/kit/endpoint"

// Endpoints contains all endpoints to enable factory
type Endpoints struct {
	PostEndpoint    endpoint.Endpoint
	ActionsEndpoint endpoint.Endpoint
	GetEndpoint     endpoint.Endpoint
	ListEndpoint    endpoint.Endpoint
	HeadEndpoint    endpoint.Endpoint
	DeleteEndpoint  endpoint.Endpoint
}

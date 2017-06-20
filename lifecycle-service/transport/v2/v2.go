// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package v2

import (
	"net/http"

	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/definitions"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/endpoints"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/translators"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/transport/routes"

	"github.com/go-kit/kit/endpoint"
	kitlog "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/tracing/opentracing"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	stdopentracing "github.com/opentracing/opentracing-go"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/translators/crn"
)

// makeServerEndpoints is a helper function that returns an Endpoints struct where each endpoint invokes
// the corresponding method on the provided service.
func makeServerEndpoints(s definitions.Service, tracer stdopentracing.Tracer) *endpoints.Endpoints {
	var postEnd endpoint.Endpoint
	{
		postEnd = endpoints.MakePostEndpoint(s)
		postEnd = opentracing.TraceServer(tracer, "Post")(postEnd)
	}

	var actionsEnd endpoint.Endpoint
	{
		actionsEnd = endpoints.MakeActionsEndpoint(s)
		actionsEnd = opentracing.TraceServer(tracer, "Actions")(actionsEnd)
	}

	var getEnd endpoint.Endpoint
	{
		getEnd = endpoints.MakeGetEndpoint(s)
		getEnd = opentracing.TraceServer(tracer, "Get")(getEnd)
	}

	var headEnd endpoint.Endpoint
	{
		headEnd = endpoints.MakeHeadEndpoint(s)
		headEnd = opentracing.TraceServer(tracer, "Head")(headEnd)
	}

	var listEnd endpoint.Endpoint
	{
		listEnd = endpoints.MakeListEndpoint(s)
		listEnd = opentracing.TraceServer(tracer, "List")(listEnd)
	}

	var deleteEnd endpoint.Endpoint
	{
		deleteEnd = endpoints.MakeDeleteEndpoint(s)
		deleteEnd = opentracing.TraceServer(tracer, "Delete")(deleteEnd)
	}

	return &endpoints.Endpoints{
		PostEndpoint:    postEnd,
		ActionsEndpoint: actionsEnd,
		GetEndpoint:     getEnd,
		HeadEndpoint:    headEnd,
		ListEndpoint:    listEnd,
		DeleteEndpoint:  deleteEnd,
	}
}

// sets the secrets endpoints to be used by the lifecycle service
func setSecretsEndpoints(router *mux.Router, endpoints *endpoints.Endpoints, options []kithttp.ServerOption) {
	router.Methods(http.MethodPost).Path(routes.APIv2Secrets).Handler(kithttp.NewServer(
		endpoints.PostEndpoint,
		translators.DecodeSecretRequest,
		translators.EncodeGenericResponse,
		options...,
	))

	router.Methods(http.MethodGet).Path(routes.APIv2SecretsID).Handler(kithttp.NewServer(
		endpoints.GetEndpoint,
		translators.DecodeIDRequest,
		translators.EncodeGenericResponse,
		options...,
	))

	router.Methods(http.MethodGet).Path(routes.APIv2Secrets).Handler(kithttp.NewServer(
		endpoints.ListEndpoint,
		translators.DecodeBaseRequest,
		translators.EncodeGenericResponse,
		options...,
	))

	router.Methods(http.MethodHead).Path(routes.APIv2Secrets).Handler(kithttp.NewServer(
		endpoints.HeadEndpoint,
		translators.DecodeBaseRequest,
		translators.EncodeGenericResponse,
		options...,
	))

	router.Methods(http.MethodDelete).Path(routes.APIv2SecretsID).Handler(kithttp.NewServer(
		endpoints.DeleteEndpoint,
		translators.DecodeIDRequest,
		translators.EncodeGenericResponse,
		options...,
	))
}

func setKeysEndpoints(router *mux.Router, endpoints *endpoints.Endpoints, options []kithttp.ServerOption) {
	router.Methods(http.MethodPost).Path(routes.APIv2Keys).Handler(kithttp.NewServer(
		endpoints.PostEndpoint,
		translators.DecodeSecretRequest,
		translators.EncodeGenericResponse,
		options...,
	))

	// Action endpoints are all supported by "/keys" based routes
	router.Methods(http.MethodPost).Path(routes.APIv2KeysID).Handler(kithttp.NewServer(
		endpoints.ActionsEndpoint,
		translators.DecodeSecretActionRequest,
		translators.EncodeGenericResponse,
		options...,
	))

	router.Methods(http.MethodGet).Path(routes.APIv2KeysID).Handler(kithttp.NewServer(
		endpoints.GetEndpoint,
		translators.DecodeIDRequest,
		translators.EncodeGenericResponse,
		options...,
	))

	router.Methods(http.MethodGet).Path(routes.APIv2Keys).Handler(kithttp.NewServer(
		endpoints.ListEndpoint,
		translators.DecodeBaseRequest,
		translators.EncodeGenericResponse,
		options...,
	))

	router.Methods(http.MethodHead).Path(routes.APIv2Keys).Handler(kithttp.NewServer(
		endpoints.HeadEndpoint,
		translators.DecodeBaseRequest,
		translators.EncodeGenericResponse,
		options...,
	))

	router.Methods(http.MethodDelete).Path(routes.APIv2KeysID).Handler(kithttp.NewServer(
		endpoints.DeleteEndpoint,
		translators.DecodeIDRequest,
		translators.EncodeGenericResponse,
		options...,
	))
}

// MakeHandler returns a handler for the secret service.
func MakeHandler(service definitions.Service, tracer stdopentracing.Tracer, logger kitlog.Logger) http.Handler {
	routeHandler := mux.NewRouter()
	endpoints := makeServerEndpoints(service, tracer)
	options := []kithttp.ServerOption{
		kithttp.ServerErrorLogger(logger),
		kithttp.ServerErrorEncoder(translators.EncodeError),
		kithttp.ServerBefore(kithttp.PopulateRequestContext, crn.ToHTTPContext()),
	}

	setKeysEndpoints(routeHandler, endpoints, options)
	setSecretsEndpoints(routeHandler, endpoints, options)

	return routeHandler
}

// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package transport

import (
	"net/http"

	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/definitions"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/transport/v2"

	kitlog "github.com/go-kit/kit/log"
	stdopentracing "github.com/opentracing/opentracing-go"
)

// MakeHandlerV2 returns a handler for v2 version of the secret service.
func MakeHandlerV2(service definitions.Service, tracer stdopentracing.Tracer, logger kitlog.Logger) http.Handler {
	return v2.MakeHandler(service, tracer, logger)
}

// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package v2

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/service/tester"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/transport/routes"

	kitlog "github.com/go-kit/kit/log"
	stdopentracing "github.com/opentracing/opentracing-go"
)

var service tester.ServiceTester
var tracer stdopentracing.Tracer

func init() {
	service = tester.NewServiceTester()
	tracer = stdopentracing.GlobalTracer()
}

func TestMakeServerEndpoints(t *testing.T) {

	serviceEndpoints := makeServerEndpoints(service, tracer)

	if serviceEndpoints == nil {
		t.Fail()
	}

	if serviceEndpoints.PostEndpoint == nil {
		t.Fail()
	}

	if serviceEndpoints.ActionsEndpoint == nil {
		t.Fail()
	}

	if serviceEndpoints.GetEndpoint == nil {
		t.Fail()
	}

	if serviceEndpoints.HeadEndpoint == nil {
		t.Fail()
	}

	if serviceEndpoints.ListEndpoint == nil {
		t.Fail()
	}

	if serviceEndpoints.DeleteEndpoint == nil {
		t.Fail()
	}
}

func TestMakeHandler(t *testing.T) {
	logger := kitlog.NewNopLogger()

	handler := MakeHandler(service, tracer, logger)

	if handler == nil {
		t.Fatal()
	}

	testServer := httptest.NewServer(handler)

	defer testServer.Close()

	// look for forbidden status on get. since we know that the role check is the
	// first thing we do, check for that.
	// TODO: if role check is ever removed from the get for any reason, this test will need
	// to be updated. TSC June 5th, 2017
	respSecrets, _ := http.Get(testServer.URL + routes.APIv2Secrets)
	if want, have := http.StatusForbidden, respSecrets.StatusCode; want != have {
		t.Errorf("want %d, have %d", want, have)
	}

	respKeys, _ := http.Get(testServer.URL + routes.APIv2Keys)
	if want, have := http.StatusForbidden, respKeys.StatusCode; want != have {
		t.Errorf("want %d, have %d", want, have)
	}
}

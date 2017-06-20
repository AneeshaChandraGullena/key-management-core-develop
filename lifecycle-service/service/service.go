// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package service

import (
	"os"

	"github.com/go-kit/kit/log"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/definitions"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/keystore"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/service/analytics"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/service/basic"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/service/inmem"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/service/instrumenting"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/service/logging"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-consts"
)

var backEndStrategy keystore.Type

func init() {
	mock, _ := os.LookupEnv(constants.MockEnv)

	if mock == constants.TestMock {
		backEndStrategy = keystore.Mock
	} else {
		backEndStrategy = keystore.Barbican
	}
}

// NewInmemService creates a new service that uses an in memory db
func NewInmemService() definitions.Service {
	return inmem.Service()
}

// NewBasicService returns a naïve, stateless implementation of Service.
func NewBasicService() definitions.Service {
	var logger log.Logger
	logger = log.NewLogfmtLogger(os.Stderr)
	logger = log.With(logger, "ts", log.DefaultTimestampUTC,
		"service", "HTTP Lifecycle BasicService",
		"caller", log.DefaultCaller)

	return basic.Service(logger, backEndStrategy)
}

// NewInstrumentingService returns an instance of an instrumenting Service.
func NewInstrumentingService(service definitions.Service) definitions.Service {
	return instrumenting.Service(service)
}

// NewLoggingService returns a new instance of a logging Service
func NewLoggingService(logger log.Logger, service definitions.Service) definitions.Service {
	return logging.Service(logger, service)
}

// NewAnalyticsService returns a new instance of a analytics middleware.
func NewAnalyticsService(env string, region string, proxy string, service definitions.Service) definitions.Service {
	return analytics.Service(env, region, proxy, service)
}

// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package logging

import (
	"time"

	"context"

	"github.com/go-kit/kit/log"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/definitions"
	corecomms "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-config"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
)

type loggingService struct {
	definitions.Service
	log.Logger
}

// Service returns a new instance of a logging Service
func Service(logger log.Logger, service definitions.Service) definitions.Service {
	return &loggingService{
		Service: service,
		Logger:  logger,
	}
}

func timeout(duration time.Duration) bool {
	config := configuration.Get()
	acceptableTime := time.Duration(config.GetInt("timeouts.acceptableWriteTimeout"))
	if acceptableTime.Seconds() < duration.Seconds() {
		return true
	}
	return false
}

func logMethod(loggingMiddleWare *loggingService, begin time.Time, method string, request communications.Request, err error) {
	//TODO elo 06/30/2016 convert to CADF logging?
	since := time.Since(begin)
	entries := []interface{}{"method", method, "took", since}

	if headers := request.GetHeaders(); headers != nil && headers.CorrelationID != "" {
		entries = append(entries, "correlation_id", headers.CorrelationID)
	}

	if err != nil {
		entries = append(entries, "err", err)
	}

	if timeout(since) {
		entries = append(entries, "timeout", true)
	}

	errLog := loggingMiddleWare.Log(entries...)
	if errLog != nil {
		panic("cannot log " + method + " do to " + errLog.Error())
	}
}

func (loggingMiddleWare *loggingService) Post(ctx context.Context, request *communications.SecretRequest) (response *communications.SecretsResponse, err error) {
	defer func(begin time.Time) { logMethod(loggingMiddleWare, begin, "Post", request, err) }(time.Now())
	return loggingMiddleWare.Service.Post(ctx, request)
}

func (loggingMiddleWare *loggingService) Actions(ctx context.Context, request *corecomms.SecretActionRequest) (response *corecomms.SecretActionResponse, err error) {
	defer func(begin time.Time) { logMethod(loggingMiddleWare, begin, "Actions", request, err) }(time.Now())
	return loggingMiddleWare.Service.Actions(ctx, request)
}

func (loggingMiddleWare *loggingService) Get(ctx context.Context, request *communications.IDRequest) (response *communications.SecretsResponse, err error) {
	defer func(begin time.Time) { logMethod(loggingMiddleWare, begin, "Get", request, err) }(time.Now())
	return loggingMiddleWare.Service.Get(ctx, request)
}

func (loggingMiddleWare *loggingService) Head(ctx context.Context, request *communications.BaseRequest) (response *communications.NumberResponse, err error) {
	defer func(begin time.Time) { logMethod(loggingMiddleWare, begin, "Head", request, err) }(time.Now())
	return loggingMiddleWare.Service.Head(ctx, request)
}

func (loggingMiddleWare *loggingService) List(ctx context.Context, request *communications.BaseRequest) (response *communications.SecretsResponse, err error) {
	defer func(begin time.Time) { logMethod(loggingMiddleWare, begin, "List", request, err) }(time.Now())
	return loggingMiddleWare.Service.List(ctx, request)
}

func (loggingMiddleWare *loggingService) Delete(ctx context.Context, request *communications.IDRequest) (response *communications.SecretsResponse, err error) {
	defer func(begin time.Time) { logMethod(loggingMiddleWare, begin, "Delete", request, err) }(time.Now())
	return loggingMiddleWare.Service.Delete(ctx, request)
}

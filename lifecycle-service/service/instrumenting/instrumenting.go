// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package instrumenting

import (
	"strconv"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics/statsd"

	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/definitions"
	corecomms "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/errors"

	"context"
)

var (
	statsdReporter *statsd.Statsd
)

const (
	reportInterval float64 = 30
)

func init() {
	statsdReporter = statsd.New("lifecycle-service.", log.NewNopLogger())

	// TODO: the Duration for the  Ticker below and the IP number need to be moved to a configuration eventually
	// so that they can be changed dynamically through configuration. TSC May 19th, 2017
	go func() {
		ticker := time.NewTicker(time.Second)
		statsdReporter.SendLoop(ticker.C, "udp", "127.0.0.1:8125")
	}()
}

type instrumentingService struct {
	definitions.Service
	reporter *statsd.Statsd
}

// Service returns an instance of an instrumenting Service.
func Service(service definitions.Service) definitions.Service {

	return &instrumentingService{
		reporter: statsdReporter,
		Service:  service,
	}
}

// return type is only used for tests
func updateServiceErrStatusCounter(instrumentingMiddleWare *instrumentingService, op string, err error) {
	statusCode := int((httperrors.ConvertError(err)).StatusCode)
	errBucketName := op + "." + strconv.Itoa(statusCode)
	statusCount := instrumentingMiddleWare.reporter.NewCounter(errBucketName, reportInterval)
	statusCount.Add(1)
}

// return type is only used for tests
func updateServiceResponseTime(instrumentingMiddleWare *instrumentingService, op string, rtime time.Duration) {
	responseTime := float64(rtime)
	responseTimeBucketName := op + "." + "ResponsesTime"
	timer := instrumentingMiddleWare.reporter.NewTiming(responseTimeBucketName, reportInterval)
	timer.Observe(responseTime)
}

func instrumentMethod(instrumentingMiddleWare *instrumentingService, begin time.Time, method string, err error) {
	ptime := time.Since(begin)
	updateServiceResponseTime(instrumentingMiddleWare, method, ptime)
	if err != nil {
		updateServiceErrStatusCounter(instrumentingMiddleWare, method, err)
	}
}

func (instrumentingMiddleWare *instrumentingService) Post(ctx context.Context, request *communications.SecretRequest) (response *communications.SecretsResponse, err error) {
	defer func(begin time.Time) { instrumentMethod(instrumentingMiddleWare, begin, "Post", err) }(time.Now())
	return instrumentingMiddleWare.Service.Post(ctx, request)
}

func (instrumentingMiddleWare *instrumentingService) Actions(ctx context.Context, request *corecomms.SecretActionRequest) (response *corecomms.SecretActionResponse, err error) {
	defer func(begin time.Time) { instrumentMethod(instrumentingMiddleWare, begin, "Actions", err) }(time.Now())
	return instrumentingMiddleWare.Service.Actions(ctx, request)
}

func (instrumentingMiddleWare *instrumentingService) Get(ctx context.Context, request *communications.IDRequest) (response *communications.SecretsResponse, err error) {
	defer func(begin time.Time) { instrumentMethod(instrumentingMiddleWare, begin, "Get", err) }(time.Now())
	return instrumentingMiddleWare.Service.Get(ctx, request)
}

func (instrumentingMiddleWare *instrumentingService) Head(ctx context.Context, request *communications.BaseRequest) (response *communications.NumberResponse, err error) {
	defer func(begin time.Time) { instrumentMethod(instrumentingMiddleWare, begin, "Head", err) }(time.Now())
	return instrumentingMiddleWare.Service.Head(ctx, request)
}

func (instrumentingMiddleWare *instrumentingService) List(ctx context.Context, request *communications.BaseRequest) (response *communications.SecretsResponse, err error) {
	defer func(begin time.Time) { instrumentMethod(instrumentingMiddleWare, begin, "List", err) }(time.Now())
	return instrumentingMiddleWare.Service.List(ctx, request)
}

func (instrumentingMiddleWare *instrumentingService) Delete(ctx context.Context, request *communications.IDRequest) (response *communications.SecretsResponse, err error) {
	defer func(begin time.Time) { instrumentMethod(instrumentingMiddleWare, begin, "Delete", err) }(time.Now())
	return instrumentingMiddleWare.Service.Delete(ctx, request)
}

// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package analytics

import (
	"fmt"
	"testing"

	"context"

	segmentio "github.com/segmentio/analytics-go"

	corecomms "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/communications"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/service/tester"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-config"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
)

var testService *analyticsService
var fService tester.ServiceTester

func init() {
	fService = tester.NewServiceTester()

	client := segmentio.New(configuration.Get().GetString("analytics.key"))
	client.Endpoint = "localhost"

	testService = &analyticsService{
		fService,
		"dev",
		"dal09",
		client,
	}
}

func TestService(t *testing.T) {
	service := Service("", "", "", fService)

	if service == nil {
		t.Fail()
	}
}

func TestServicePanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovered from %v error\n", r)
		}
	}()

	service := Service("", "", ":stuff", fService)

	if service != nil {
		t.Fail()
	}
}

func TestPost(t *testing.T) {
	ctx := context.Background()

	request := communications.NewSecretRequest()
	_, err := testService.Post(ctx, request)
	if err == nil {
		t.Fail()
	}

	request.Headers.UserID = "test-user-id"
	_, err = testService.Post(ctx, request)
	if err != nil {
		t.Fail()
	}
}

func TestActions(t *testing.T) {
	ctx := context.Background()

	request := corecomms.NewSecretActionRequest()
	_, err := testService.Actions(ctx, request)
	if err == nil {
		t.Fail()
	}

	request.Headers.UserID = "test-user-id"
	_, err = testService.Actions(ctx, request)
	if err != nil {
		t.Fail()
	}
}

func TestGet(t *testing.T) {
	ctx := context.Background()

	request := communications.NewIDRequest()
	_, err := testService.Get(ctx, request)
	if err == nil {
		t.Fail()
	}

	request.Headers.UserID = "test-user-id"
	_, err = testService.Get(ctx, request)
	if err != nil {
		t.Fail()
	}
}

func TestHead(t *testing.T) {
	ctx := context.Background()

	request := communications.NewBaseRequest()
	_, err := testService.Head(ctx, request)
	if err == nil {
		t.Fail()
	}

	request.Headers.UserID = "test-user-id"
	_, err = testService.Head(ctx, request)
	if err != nil {
		t.Fail()
	}
}

func TestList(t *testing.T) {
	ctx := context.Background()

	request := communications.NewBaseRequest()
	_, err := testService.List(ctx, request)
	if err == nil {
		t.Fail()
	}

	request.Headers.UserID = "test-user-id"
	_, err = testService.List(ctx, request)
	if err != nil {
		t.Fail()
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()

	request := communications.NewIDRequest()
	_, err := testService.Delete(ctx, request)
	if err == nil {
		t.Fail()
	}

	request.Headers.UserID = "test-user-id"
	_, err = testService.Delete(ctx, request)
	if err != nil {
		t.Fail()
	}
}

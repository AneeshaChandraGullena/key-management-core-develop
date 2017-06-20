// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package logging

import (
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/go-kit/kit/log"

	"context"

	corecomms "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/communications"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/service/tester"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
)

var testService *loggingService
var fLogger *fakeLogger
var fService tester.ServiceTester

// Methods used by service
var (
	post    = "post"
	actions = "actions"
	head    = "head"
	get     = "get"
	list    = "list"
	delete  = "delete"
)

type fakeLogger struct {
	logs  map[string]string
	force bool
}

// Function to meet go-kit logger interface
func (logger *fakeLogger) Log(keyval ...interface{}) error {
	if logger.force == true {
		return errors.New("force error for panic test")
	}

	if len(keyval)%2 != 0 {
		return errors.New("every key should have a value")
	}

	for i := 0; i < len(keyval)-1; i = i + 2 {
		key := keyval[i].(string)
		var value string

		valueIface := keyval[i+1]
		switch t := valueIface.(type) {
		case string:
			value = valueIface.(string)
		case error:
			value = valueIface.(error).Error()
		case bool:
			value = strconv.FormatBool(valueIface.(bool))
		case time.Duration:
			value = valueIface.(time.Duration).String()
		default:
			return fmt.Errorf("Unsupported log value type %v", t)
		}
		logger.logs[key] = value
	}
	return nil
}

func (logger *fakeLogger) forceError() {
	logger.force = true
}

func (logger *fakeLogger) suppressError() {
	logger.force = false
}

// Helper test functions for the testLogger
func reviewLogs() map[string]string {
	return fLogger.logs
}

func cleanLogs() {
	fLogger.logs = make(map[string]string)
}

func init() {
	testService = new(loggingService)

	fLogger = new(fakeLogger)

	fService = tester.NewServiceTester()

	testService.Service = fService
	testService.Logger = fLogger

	// make map
	cleanLogs()
}

func TestService(t *testing.T) {
	service := Service(log.NewNopLogger(), fService)

	if service == nil {
		t.Fail()
	}
}

func TestTimeout(t *testing.T) {
	var durationA time.Duration = 4
	var durationB time.Duration = 12

	if timeout(durationA) {
		t.Fail()
	}

	if !timeout(durationB) {
		t.Fail()
	}
}

func TestLogMethod(t *testing.T) {
	now := time.Now()
	request := communications.NewBaseRequest()
	request.Headers.CorrelationID = "test-id"
	err := errors.New("Test Error")
	method := "test"

	time.Sleep(8)

	logMethod(testService, now, method, request, err)

	logs := reviewLogs()
	if logs["method"] != method {
		t.Fail()
	}

	if logs["correlation_id"] != request.Headers.CorrelationID {
		t.Fail()
	}

	if logs["err"] != err.Error() {
		t.Fail()
	}

	if logs["timeout"] != "true" {
		t.Fail()
	}

	cleanLogs()
}

func TestLogMethodPanic(t *testing.T) {
	fLogger.forceError()

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovered from %v error\n", r)
			fLogger.suppressError()
			cleanLogs()
		}
	}()

	now := time.Now()
	request := communications.NewBaseRequest()
	request.Headers.CorrelationID = "test-id"
	err := errors.New("Test Error")
	method := "test"

	logMethod(testService, now, method, request, err)
}

// helper for testing the different methods used by logging service
func testMethod(t *testing.T, method string, request communications.Request, expectedError error) {
	ctx := context.Background()

	var err error
	switch method {
	case post:
		_, err = testService.Post(ctx, request.(*communications.SecretRequest))
	case actions:
		_, err = testService.Actions(ctx, request.(*corecomms.SecretActionRequest))
	case get:
		_, err = testService.Get(ctx, request.(*communications.IDRequest))
	case head:
		_, err = testService.Head(ctx, request.(*communications.BaseRequest))
	case list:
		_, err = testService.List(ctx, request.(*communications.BaseRequest))
	case delete:
		_, err = testService.Delete(ctx, request.(*communications.IDRequest))
	}

	if expectedError != nil {
		if err == nil {
			t.Fail()
		}

		if expectedError.Error() != err.Error() {
			t.Fail()
		}

		return
	}
	if err != nil {
		t.Fail()
	}
}

func TestPost(t *testing.T) {
	request := communications.NewSecretRequest()

	testMethod(t, post, request, nil)

	testError := errors.New("test-error")
	fService.InjectError(testError)

	testMethod(t, post, request, testError)
	fService.RemoveError()

	logs := reviewLogs()
	if logs["err"] != testError.Error() {
		t.Fail()
	}

	cleanLogs()
}

func TestActions(t *testing.T) {
	request := corecomms.NewSecretActionRequest()

	testMethod(t, actions, request, nil)

	testError := errors.New("test-error")
	fService.InjectError(testError)

	testMethod(t, actions, request, testError)
	fService.RemoveError()

	logs := reviewLogs()
	if logs["err"] != testError.Error() {
		t.Fail()
	}

	cleanLogs()
}

func TestGet(t *testing.T) {
	request := communications.NewIDRequest()

	testMethod(t, get, request, nil)

	testError := errors.New("test-error")
	fService.InjectError(testError)

	testMethod(t, get, request, testError)
	fService.RemoveError()

	logs := reviewLogs()
	if logs["err"] != testError.Error() {
		t.Fail()
	}

	cleanLogs()
}

func TestHead(t *testing.T) {
	request := communications.NewBaseRequest()

	testMethod(t, head, request, nil)

	testError := errors.New("test-error")
	fService.InjectError(testError)

	testMethod(t, head, request, testError)
	fService.RemoveError()

	logs := reviewLogs()
	if logs["err"] != testError.Error() {
		t.Fail()
	}

	cleanLogs()
}

func TestList(t *testing.T) {
	request := communications.NewBaseRequest()

	testMethod(t, list, request, nil)

	testError := errors.New("test-error")
	fService.InjectError(testError)

	testMethod(t, list, request, testError)
	fService.RemoveError()

	logs := reviewLogs()
	if logs["err"] != testError.Error() {
		t.Fail()
	}

	cleanLogs()
}

func TestDelete(t *testing.T) {
	request := communications.NewIDRequest()

	testMethod(t, delete, request, nil)

	testError := errors.New("test-error")
	fService.InjectError(testError)

	testMethod(t, delete, request, testError)
	fService.RemoveError()

	logs := reviewLogs()
	if logs["err"] != testError.Error() {
		t.Fail()
	}

	cleanLogs()
}

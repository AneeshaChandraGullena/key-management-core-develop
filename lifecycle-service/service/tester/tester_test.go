// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package tester

import (
	"errors"
	"testing"

	"context"

	corecomms "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
)

func TestNewServiceTester(t *testing.T) {
	if testService := NewServiceTester(); testService == nil {
		t.Fail()
	}
}

func TestTesterService(t *testing.T) {
	testService := new(testerService)
	testError := errors.New("test-error")
	ctx := context.Background()

	// Test inject error
	testService.InjectError(testError)

	if _, err := testService.Post(ctx, communications.NewSecretRequest()); err.Error() != testError.Error() {
		t.Fail()
	}

	if _, err := testService.Actions(ctx, corecomms.NewSecretActionRequest()); err.Error() != testError.Error() {
		t.Fail()
	}

	if _, err := testService.Get(ctx, communications.NewIDRequest()); err.Error() != testError.Error() {
		t.Fail()
	}

	if _, err := testService.Head(ctx, communications.NewBaseRequest()); err.Error() != testError.Error() {
		t.Fail()
	}

	if _, err := testService.List(ctx, communications.NewBaseRequest()); err.Error() != testError.Error() {
		t.Fail()
	}

	if _, err := testService.Delete(ctx, communications.NewIDRequest()); err.Error() != testError.Error() {
		t.Fail()
	}

	// Test remove error
	testService.RemoveError()

	if _, err := testService.Post(ctx, communications.NewSecretRequest()); err != nil {
		t.Fail()
	}

	if _, err := testService.Actions(ctx, corecomms.NewSecretActionRequest()); err != nil {
		t.Fail()
	}

	if _, err := testService.Get(ctx, communications.NewIDRequest()); err != nil {
		t.Fail()
	}

	if _, err := testService.Head(ctx, communications.NewBaseRequest()); err != nil {
		t.Fail()
	}

	if _, err := testService.List(ctx, communications.NewBaseRequest()); err != nil {
		t.Fail()
	}

	if _, err := testService.Delete(ctx, communications.NewIDRequest()); err != nil {
		t.Fail()
	}
}

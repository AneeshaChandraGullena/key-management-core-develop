// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package instrumenting

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
	"testing"
	"time"

	corecomms "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/communications"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/service/tester"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
)

var testService *instrumentingService
var fService tester.ServiceTester

func init() {
	fService = tester.NewServiceTester()

	testService = &instrumentingService{
		reporter: statsdReporter,
		Service:  fService,
	}
}

func stats(w io.WriterTo, regex string) (count int, err error) {
	re := regexp.MustCompile(regex)
	buf := &bytes.Buffer{}
	w.WriteTo(buf)
	s := bufio.NewScanner(buf)

	for s.Scan() {
		match := re.FindStringSubmatch(s.Text())
		if len(match) == 0 {
			return 0, errors.New("Unable to find match")
		}
		count++
	}
	return count, nil
}

func TestService(t *testing.T) {
	service := Service(fService)
	if service == nil {
		t.Fail()
	}
}

func TestUpdateServiceErrStatusCounter(t *testing.T) {
	method := "TestUpdateServiceErrStatusCounter"
	err := errors.New("test-error")

	prefix, name := "lifecycle-service.", method
	regex := `^` + prefix + name + `.+\|c|ms$`
	updateServiceErrStatusCounter(testService, method, err)

	sum, err := stats(statsdReporter, regex)
	if err != nil {
		t.Errorf("Unexpected Error %s", err)
	}

	if sum != 1 {
		t.Errorf("Expected 1, received %v", sum)
	}
}

func TestUpdateServiceResponseTime(t *testing.T) {
	method := "TestUpdateServiceResponseTime"
	var duration time.Duration = 30

	prefix, name := "lifecycle-service.", method
	regex := `^` + prefix + name + `.+\|c|ms$`
	updateServiceResponseTime(testService, method, duration)

	sum, err := stats(statsdReporter, regex)
	if err != nil {
		t.Errorf("Unexpected Error %s", err)
	}

	if sum != 1 {
		t.Errorf("Expected 1, received %v", sum)
	}
}

func TestInstrumentMethod(t *testing.T) {
	method := "TestInstrumentMethod"

	now := time.Now()
	err := errors.New("test-error")

	prefix, name := "lifecycle-service.", method
	regex := `^` + prefix + name + `.+\|c|ms$`
	instrumentMethod(testService, now, method, err)

	sum, err := stats(statsdReporter, regex)
	if err != nil {
		t.Errorf("Unexpected Error %s", err)
	}

	if sum != 2 {
		t.Errorf("Expected 2, received %v", sum)
	}
}

func TestPost(t *testing.T) {
	ctx := context.Background()
	fService.InjectError(errors.New(http.StatusText(http.StatusForbidden)))

	method := "Post"

	prefix, name := "lifecycle-service.", method
	regex := `^` + prefix + name + `.+\|c|ms$`

	_, err := testService.Post(ctx, communications.NewSecretRequest())
	fService.RemoveError()
	if err == nil {
		t.Fail()
	}

	sum, err := stats(statsdReporter, regex)
	if err != nil {
		t.Errorf("Unexpected Error %s", err)
	}

	if sum != 2 {
		t.Errorf("Expected 2, received %v", sum)
	}
}

func TestActions(t *testing.T) {
	ctx := context.Background()
	fService.InjectError(errors.New(http.StatusText(http.StatusForbidden)))

	method := "Actions"

	prefix, name := "lifecycle-service.", method
	regex := `^` + prefix + name + `.+\|c|ms$`

	_, err := testService.Actions(ctx, corecomms.NewSecretActionRequest())
	fService.RemoveError()
	if err == nil {
		t.Fail()
	}

	sum, err := stats(statsdReporter, regex)
	if err != nil {
		t.Errorf("Unexpected Error %s", err)
	}

	if sum != 2 {
		t.Errorf("Expected 2, received %v", sum)
	}
}

func TestGet(t *testing.T) {
	ctx := context.Background()
	fService.InjectError(errors.New(http.StatusText(http.StatusForbidden)))

	method := "Get"

	prefix, name := "lifecycle-service.", method
	regex := `^` + prefix + name + `.+\|c|ms$`

	_, err := testService.Get(ctx, communications.NewIDRequest())
	fService.RemoveError()
	if err == nil {
		t.Fail()
	}

	sum, err := stats(statsdReporter, regex)
	if err != nil {
		t.Errorf("Unexpected Error %s", err)
	}

	if sum != 2 {
		t.Errorf("Expected 2, received %v", sum)
	}
}

func TestHead(t *testing.T) {
	ctx := context.Background()
	fService.InjectError(errors.New(http.StatusText(http.StatusForbidden)))

	method := "Head"

	prefix, name := "lifecycle-service.", method
	regex := `^` + prefix + name + `.+\|c|ms$`

	_, err := testService.Head(ctx, communications.NewBaseRequest())
	fService.RemoveError()
	if err == nil {
		t.Fail()
	}

	sum, err := stats(statsdReporter, regex)
	if err != nil {
		t.Errorf("Unexpected Error %s", err)
	}

	if sum != 2 {
		t.Errorf("Expected 2, received %v", sum)
	}
}
func TestList(t *testing.T) {
	ctx := context.Background()
	fService.InjectError(errors.New(http.StatusText(http.StatusForbidden)))

	method := "List"

	prefix, name := "lifecycle-service.", method
	regex := `^` + prefix + name + `.+\|c|ms$`

	_, err := testService.List(ctx, communications.NewBaseRequest())
	fService.RemoveError()
	if err == nil {
		t.Fail()
	}

	sum, err := stats(statsdReporter, regex)
	if err != nil {
		t.Errorf("Unexpected Error %s", err)
	}

	if sum != 2 {
		t.Errorf("Expected 2, received %v", sum)
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	fService.InjectError(errors.New(http.StatusText(http.StatusForbidden)))

	method := "Delete"

	prefix, name := "lifecycle-service.", method
	regex := `^` + prefix + name + `.+\|c|ms$`

	_, err := testService.Delete(ctx, communications.NewIDRequest())
	fService.RemoveError()
	if err == nil {
		t.Fail()
	}

	sum, err := stats(statsdReporter, regex)
	if err != nil {
		t.Errorf("Unexpected Error %s", err)
	}

	if sum != 2 {
		t.Errorf("Expected 2, received %v", sum)
	}
}

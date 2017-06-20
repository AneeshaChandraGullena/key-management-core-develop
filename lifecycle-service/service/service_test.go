// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package service

import (
	"testing"

	"github.com/go-kit/kit/log"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/service/tester"
)

var fService tester.ServiceTester

func init() {
	fService = tester.NewServiceTester()
}

func TestNewInmemService(t *testing.T) {
	if svc := NewInmemService(); svc == nil {
		t.Fail()
	}
}

func TestNewBasicService(t *testing.T) {
	if svc := NewBasicService(); svc == nil {
		t.Fail()
	}
}

func TestNewInstrumentingService(t *testing.T) {
	if svc := NewInstrumentingService(fService); svc == nil {
		t.Fail()
	}
}

func TestNewLoggingService(t *testing.T) {
	if svc := NewLoggingService(log.NewNopLogger(), fService); svc == nil {
		t.Fail()
	}
}

func TestNewAnalyticsService(t *testing.T) {
	if svc := NewAnalyticsService("", "", "", fService); svc == nil {
		t.Fail()
	}
}

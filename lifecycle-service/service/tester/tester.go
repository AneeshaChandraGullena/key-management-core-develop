// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package tester

import (
	"context"

	svcDef "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/definitions"
	corecomms "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
)

// ServiceTester is an interface extending the std Service definition for provision services
type ServiceTester interface {
	// Basic methods need to meed service definition
	svcDef.Service

	// Test Helpers
	InjectError(err error)
	RemoveError()
}

type testerService struct {
	e error
}

func (svc *testerService) InjectError(err error) {
	svc.e = err
}

func (svc *testerService) RemoveError() {
	svc.e = nil
}

func (svc *testerService) Post(ctx context.Context, request *communications.SecretRequest) (*communications.SecretsResponse, error) {
	return nil, svc.e
}

func (svc *testerService) Actions(ctx context.Context, request *corecomms.SecretActionRequest) (*corecomms.SecretActionResponse, error) {
	return nil, svc.e
}

func (svc *testerService) Get(ctx context.Context, request *communications.IDRequest) (*communications.SecretsResponse, error) {
	return nil, svc.e
}

func (svc *testerService) Head(ctx context.Context, request *communications.BaseRequest) (*communications.NumberResponse, error) {
	return nil, svc.e
}

func (svc *testerService) List(ctx context.Context, request *communications.BaseRequest) (*communications.SecretsResponse, error) {
	return nil, svc.e
}

func (svc *testerService) Delete(ctx context.Context, request *communications.IDRequest) (*communications.SecretsResponse, error) {
	return nil, svc.e
}

// NewServiceTester will return a new ServiceTester that can be used for testing
func NewServiceTester() ServiceTester {
	return new(testerService)
}

// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package endpoints

import (
	"testing"

	"context"

	corecomms "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/communications"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/service/tester"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
)

var service tester.ServiceTester

func init() {
	service = tester.NewServiceTester()
}

func TestPostEndpoint(t *testing.T) {
	ctx := context.Background()

	endpoint := MakePostEndpoint(service)

	if endpoint == nil {
		t.Errorf("CreateEndpoint is not defined")
	}

	req := communications.NewSecretRequest()
	_, errEndpoint := endpoint(ctx, req)
	if errEndpoint != nil {
		t.Errorf("CreateEndpoint is not defined")
	}

	badReq := communications.NewIDRequest()
	_, errEndpoint = endpoint(ctx, badReq)
	if errEndpoint == nil {
		t.Error("Expected Error")
	}
}

func TestActionsEndpoint(t *testing.T) {
	ctx := context.Background()

	endpoint := MakeActionsEndpoint(service)

	if endpoint == nil {
		t.Errorf("GetEndpoint is not defined")
	}

	req := corecomms.NewSecretActionRequest()
	_, errEndpoint := endpoint(ctx, req)
	if errEndpoint != nil {
		t.Errorf("GetEndpoint is not defined")
	}

	badReq := communications.NewBaseRequest()
	_, errEndpoint = endpoint(ctx, badReq)
	if errEndpoint == nil {
		t.Error("Expected Error")
	}
}

func TestGetEndpoint(t *testing.T) {
	ctx := context.Background()

	endpoint := MakeGetEndpoint(service)

	if endpoint == nil {
		t.Errorf("GetEndpoint is not defined")
	}

	req := communications.NewIDRequest()
	_, errEndpoint := endpoint(ctx, req)
	if errEndpoint != nil {
		t.Errorf("GetEndpoint is not defined")
	}

	badReq := communications.NewBaseRequest()
	_, errEndpoint = endpoint(ctx, badReq)
	if errEndpoint == nil {
		t.Error("Expected Error")
	}
}

func TestListEndpoint(t *testing.T) {
	ctx := context.Background()

	endpoint := MakeListEndpoint(service)

	if endpoint == nil {
		t.Errorf("ListEndpoint is not defined")
	}

	req := communications.NewBaseRequest()
	_, errEndpoint := endpoint(ctx, req)
	if errEndpoint != nil {
		t.Errorf("ListEndpoint is not defined")
	}

	badReq := communications.NewIDRequest()
	_, errEndpoint = endpoint(ctx, badReq)
	if errEndpoint == nil {
		t.Error("Expected Error")
	}
}

func TestHeadEndpoint(t *testing.T) {
	ctx := context.Background()

	endpoint := MakeHeadEndpoint(service)

	if endpoint == nil {
		t.Errorf("ListEndpoint is not defined")
	}

	req := communications.NewBaseRequest()
	_, errEndpoint := endpoint(ctx, req)
	if errEndpoint != nil {
		t.Errorf("ListEndpoint is not defined")
	}

	badReq := communications.NewIDRequest()
	_, errEndpoint = endpoint(ctx, badReq)
	if errEndpoint == nil {
		t.Error("Expected Error")
	}
}

func TestDeleteEndpoint(t *testing.T) {
	ctx := context.Background()

	endpoint := MakeDeleteEndpoint(service)

	if endpoint == nil {
		t.Errorf("GetDeleteEndpoint is not defined")
	}

	req := communications.NewIDRequest()
	_, errEndpoint := endpoint(ctx, req)
	if errEndpoint != nil {
		t.Errorf("GetDeleteEndpoint is not defined")
	}

	badReq := communications.NewBaseRequest()
	_, errEndpoint = endpoint(ctx, badReq)
	if errEndpoint == nil {
		t.Error("Expected Error")
	}
}

// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package inmem

import (
	"testing"

	"context"

	uuid "github.com/satori/go.uuid"

	corecomms "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/secrets"
)

var testService *inmemService

func seed() (id string) {
	id = uuid.NewV4().String()
	testSecret := secrets.NewSecret()
	testSecret.ID = id
	testService.data[id] = testSecret
	return
}

func clean() {
	testService.data = make(map[string]*secrets.Secret)
}

func init() {
	testService = new(inmemService)
	testService.data = make(map[string]*secrets.Secret)
}

func TestService(t *testing.T) {
	service := Service()

	if service == nil {
		t.Fail()
	}
}

func testPost(t *testing.T, request *communications.SecretRequest) *secrets.Secret {
	ctx := context.Background()

	response, err := testService.Post(ctx, request)
	if err != nil {
		t.Fail()
	}

	if response.Secrets == nil || len(response.Secrets) == 0 {
		t.Error("Expected Secret")
	}

	if response.Secrets[0].ID == "" {
		t.Error("Expected Secret with ID")
	}

	if _, errUUID := uuid.FromString(response.Secrets[0].ID); errUUID != nil {
		t.Error("Expected UUID as ID")
	}

	return response.Secrets[0]
}

func TestPost(t *testing.T) {
	// Test without includeResource
	request := communications.NewSecretRequest()
	request.Secret = secrets.NewSecret()
	testPost(t, request)

	// Test with includeResource
	request.Parameters.IncludeResource = true
	testPost(t, request)

	clean()
}

func testActions(t *testing.T, request *corecomms.SecretActionRequest) string {
	ctx := context.Background()

	_, err := testService.Actions(ctx, request)
	if err != nil {
		t.Fail()
	}

	return ""
}

func TestActions(t *testing.T) {
	// Test without includeResource
	request := corecomms.NewSecretActionRequest()
	testActions(t, request)

	clean()
}

func testGet(t *testing.T, request *communications.IDRequest, expectedError error) *secrets.Secret {
	ctx := context.Background()

	response, err := testService.Get(ctx, request)
	if expectedError != nil {
		if err == nil {
			t.Fail()
		}

		if expectedError.Error() != err.Error() {
			t.Fail()
		}

		return nil
	}
	if err != nil {
		t.Fail()
	}

	if response.Secrets == nil || len(response.Secrets) == 0 {
		t.Error("Expected Secret")
	}

	if response.Secrets[0].ID == "" {
		t.Error("Expected Secret with ID")
	}

	if request.ID != response.Secrets[0].ID {
		t.Errorf("Expected %s, received %s", request.ID, response.Secrets[0].ID)
	}

	return response.Secrets[0]
}

func TestGet(t *testing.T) {
	goodID := seed()
	badID := uuid.NewV4().String()
	request := communications.NewIDRequest()

	// Get with bad id
	request.ID = badID
	testGet(t, request, ErrNotFound)

	// Get with a good id
	request.ID = goodID
	testGet(t, request, nil)

	clean()
}

func TestPostThenGet(t *testing.T) {
	// Post a secret
	secretRequest := communications.NewSecretRequest()
	secretRequest.Secret = secrets.NewSecret()
	secretRequest.Parameters.IncludeResource = true
	secret := testPost(t, secretRequest)
	id := secret.ID

	// Get a secret
	idRequest := communications.NewIDRequest()
	idRequest.SetID(id)
	testGet(t, idRequest, nil)

	clean()
}

func testHead(t *testing.T, request *communications.BaseRequest, expectedTotal int, expectedError error) {
	ctx := context.Background()

	response, err := testService.Head(ctx, request)
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

	if response.Number != int32(expectedTotal) {
		t.Errorf("Expected %d, received %d", response.Number, expectedTotal)
	}
}

func TestHead(t *testing.T) {
	baseRequest := communications.NewBaseRequest()

	testHead(t, baseRequest, 0, nil)
	seed()
	testHead(t, baseRequest, 1, nil)
	seed()
	testHead(t, baseRequest, 2, nil)

	clean()
}

func testList(t *testing.T, request *communications.BaseRequest, expectedError error) {
	ctx := context.Background()

	_, err := testService.List(ctx, request)
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

func TestList(t *testing.T) {
	baseRequest := communications.NewBaseRequest()
	seed()
	seed()
	seed()

	parameters := baseRequest.GetParameters()
	parameters.Limit = 1
	parameters.Offset = 1
	testList(t, baseRequest, nil)
	parameters.Limit = 1
	parameters.Offset = 2
	testList(t, baseRequest, nil)
	parameters.Limit = 2
	parameters.Offset = 1
	testList(t, baseRequest, nil)
	parameters.Limit = 2
	parameters.Offset = 2
	testList(t, baseRequest, nil)

	clean()
}

func testDelete(t *testing.T, request *communications.IDRequest, expectedError error) {
	ctx := context.Background()

	id := request.ID
	response, err := testService.Delete(ctx, request)
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

	if testService.data[id] != nil {
		t.Error("Expected Delete")
	}

	if request.GetParameters().IncludeResource == true {
		if response.Secrets == nil || len(response.Secrets) == 0 {
			t.Error("Expected Secret")
		}

		if response.Secrets[0].ID == "" {
			t.Error("Expected Secret with ID")
		}

		if request.ID != response.Secrets[0].ID {
			t.Errorf("Expected %s, received %s", request.ID, response.Secrets[0].ID)
		}
	} else {
		if len(response.Secrets) != 0 {
			t.Error("Expected no Secret")
		}
	}
}

func TestDelete(t *testing.T) {
	request := communications.NewIDRequest()

	// Get with bad id
	request.ID = uuid.NewV4().String()
	testDelete(t, request, ErrNotFound)

	// Get with a good id
	request.ID = seed()
	testDelete(t, request, nil)

	request.ID = seed()
	request.Parameters.IncludeResource = true
	testDelete(t, request, nil)

	clean()
}

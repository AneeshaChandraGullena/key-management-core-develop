// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package translators

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"context"

	kithttp "github.com/go-kit/kit/transport/http"

	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/transport/routes"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/secrets"
)

func TestEncodeGetListResponse(t *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, kithttp.ContextKeyRequestMethod, http.MethodGet)
	ctx = context.WithValue(ctx, kithttp.ContextKeyRequestPath, routes.APIv2Secrets)

	secretsResponse := communications.NewSecretsResponse()
	testSecret := secrets.NewSecret()

	secretsResponse.AppendSecret(testSecret)

	recorder := httptest.NewRecorder()

	err := EncodeGenericResponse(ctx, recorder, secretsResponse)
	if err != nil {
		t.Fail()
	}

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected %d, recieved %d", http.StatusOK, recorder.Code)
	}
}

func TestEncodeDeleteResponse(t *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, kithttp.ContextKeyRequestMethod, http.MethodDelete)
	ctx = context.WithValue(ctx, kithttp.ContextKeyRequestPath, routes.APIv2SecretsID)

	secretsResponse := communications.NewSecretsResponse()
	testSecret := secrets.NewSecret()

	recorder := httptest.NewRecorder()

	err := EncodeGenericResponse(ctx, recorder, secretsResponse)
	if err != nil {
		t.Fail()
	}

	if recorder.Code != http.StatusNoContent {
		t.Errorf("Expected %d, recieved %d", http.StatusNoContent, recorder.Code)
	}

	secretsResponse.AppendSecret(testSecret)

	recorder = httptest.NewRecorder()

	err = EncodeGenericResponse(ctx, recorder, secretsResponse)
	if err != nil {
		t.Fail()
	}

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected %d, recieved %d", http.StatusOK, recorder.Code)
	}
}

func TestEncodeHeadResponse(t *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, kithttp.ContextKeyRequestMethod, http.MethodHead)
	ctx = context.WithValue(ctx, kithttp.ContextKeyRequestPath, routes.APIv2Secrets)

	numberResponse := communications.NewNumberResponse()

	recorder := httptest.NewRecorder()

	err := EncodeGenericResponse(ctx, recorder, numberResponse)
	if err != nil {
		t.Fail()
	}

	if recorder.Code != http.StatusNoContent {
		t.Errorf("Expected %d, recieved %d", http.StatusNoContent, recorder.Code)
	}
}

func TestEncodePostResponse(t *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, kithttp.ContextKeyRequestMethod, http.MethodPost)
	ctx = context.WithValue(ctx, kithttp.ContextKeyRequestPath, routes.APIv2Secrets)

	secretsResponse := communications.NewSecretsResponse()
	testSecret := secrets.NewSecret()

	secretsResponse.AppendSecret(testSecret)

	recorder := httptest.NewRecorder()

	err := EncodeGenericResponse(ctx, recorder, secretsResponse)
	if err != nil {
		t.Fail()
	}

	if recorder.Code != http.StatusCreated {
		t.Errorf("Expected %d, recieved %d", http.StatusCreated, recorder.Code)
	}
}

func TestEncodeError(t *testing.T) {
	ctx := context.Background()

	recorder := httptest.NewRecorder()

	var testInternalError error
	EncodeError(ctx, testInternalError, recorder)

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("Expected %d, recieved %d", http.StatusNoContent, recorder.Code)
	}
}

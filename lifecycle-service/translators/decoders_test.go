// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package translators

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"

	"context"

	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/actions"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-consts"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/collections"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/secrets"
)

var (
	validUser   = uuid.NewV4().String()
	invalidUser = "bad-user"
)

func TestDecodeBaseRequest(t *testing.T) {
	ctx := context.Background()

	// Bad Path: No Role

	// create test request to pass to handler
	testRequest, _ := http.NewRequest(http.MethodHead, "/test", nil)

	_, err := DecodeBaseRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", nil)

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeBaseRequest(ctx, testRequest)
	if err != nil {
		t.Fail()
	}
}

func TestDecodeIDRequest(t *testing.T) {
	ctx := context.Background()

	// Bad Path: No Role

	// create test request to pass to handler
	testRequest, _ := http.NewRequest(http.MethodHead, "/test", nil)

	_, err := DecodeIDRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", nil)

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeIDRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	goodPath := func(_ http.ResponseWriter, request *http.Request) {
		_, err := DecodeIDRequest(ctx, request)
		if err != nil {
			t.Errorf("Unexpected Error: %s", err)
		}
	}

	router := mux.NewRouter()
	router.HandleFunc("/test/{id}", goodPath).Methods(http.MethodHead)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test/"+uuid.NewV4().String(), nil)

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, testRequest)

	// Bad UUID

	badPath := func(_ http.ResponseWriter, request *http.Request) {
		_, err := DecodeIDRequest(ctx, request)
		if err == nil {
			t.Error("Error Expected")
		}
	}

	router = mux.NewRouter()
	router.HandleFunc("/test/{id}", badPath).Methods(http.MethodHead)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test/"+"2313243214", nil)

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	recorder = httptest.NewRecorder()

	router.ServeHTTP(recorder, testRequest)
}

func TestDecodeSecretRequest(t *testing.T) {
	ctx := context.Background()

	// Bad Path: No Role

	// create test request to pass to handler
	testRequest, _ := http.NewRequest(http.MethodHead, "/test", nil)

	_, err := DecodeSecretRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Bad Path: No Body

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", nil)

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Bad Path: Empty Body

	secretCollection := collections.NewSecretCollection()
	jsonReqeust, _ := json.Marshal(secretCollection)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", bytes.NewBuffer(jsonReqeust))

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Bad Path: No Resources

	secretCollection.Metadata.CollectionTotal = 1
	jsonReqeust, _ = json.Marshal(secretCollection)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", bytes.NewBuffer(jsonReqeust))

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Bad Path: No Collection Type

	secretCollection.Metadata.CollectionType = ""
	jsonReqeust, _ = json.Marshal(secretCollection)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", bytes.NewBuffer(jsonReqeust))

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Bad Path: Bad Collection Type

	secretCollection.Metadata.CollectionType = "bad-collection"
	jsonReqeust, _ = json.Marshal(secretCollection)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", bytes.NewBuffer(jsonReqeust))

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Bad Path: No Resources

	secretCollection.Metadata.CollectionType = collections.SecretMIME
	jsonReqeust, _ = json.Marshal(secretCollection)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", bytes.NewBuffer(jsonReqeust))

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Bad Path: Resources/Total mismatch

	testSecret := secrets.NewSecret()
	secretCollection.Metadata.CollectionTotal = 2
	secretCollection.Resources = append(secretCollection.Resources, testSecret)
	jsonReqeust, _ = json.Marshal(secretCollection)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", bytes.NewBuffer(jsonReqeust))

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Bad Path: Resources w/out SecretType

	secretCollection.Metadata.CollectionTotal = 1
	jsonReqeust, _ = json.Marshal(secretCollection)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", bytes.NewBuffer(jsonReqeust))

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Bad Path: Resources w/out name

	testSecret.SetSecretType("test-type")
	jsonReqeust, _ = json.Marshal(secretCollection)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", bytes.NewBuffer(jsonReqeust))

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Good Path

	testSecret.SetName("test-name")
	jsonReqeust, _ = json.Marshal(secretCollection)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", bytes.NewBuffer(jsonReqeust))

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretRequest(ctx, testRequest)
	if err != nil {
		t.Fail()
	}
}

func TestDecodeSecretsRequest(t *testing.T) {
	ctx := context.Background()

	// Bad Path: No Role

	// create test request to pass to handler
	testRequest, _ := http.NewRequest(http.MethodHead, "/test", nil)

	_, err := DecodeSecretsRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Bad Path: No Body

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", nil)

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretsRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Bad Path: Empty Body

	secretCollection := collections.NewSecretCollection()
	jsonReqeust, _ := json.Marshal(secretCollection)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", bytes.NewBuffer(jsonReqeust))

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretsRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Bad Path: No Resources

	secretCollection.Metadata.CollectionTotal = 1
	jsonReqeust, _ = json.Marshal(secretCollection)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", bytes.NewBuffer(jsonReqeust))

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretsRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Bad Path: No Collection Type

	secretCollection.Metadata.CollectionType = ""
	jsonReqeust, _ = json.Marshal(secretCollection)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", bytes.NewBuffer(jsonReqeust))

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretsRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Bad Path: Bad Collection Type

	secretCollection.Metadata.CollectionType = "bad-collection"
	jsonReqeust, _ = json.Marshal(secretCollection)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", bytes.NewBuffer(jsonReqeust))

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretsRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Bad Path: No Resources

	secretCollection.Metadata.CollectionType = collections.SecretMIME
	jsonReqeust, _ = json.Marshal(secretCollection)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", bytes.NewBuffer(jsonReqeust))

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretsRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Bad Path: Resources/Total mismatch

	testSecret := secrets.NewSecret()
	secretCollection.Metadata.CollectionTotal = 2
	secretCollection.Resources = append(secretCollection.Resources, testSecret)
	jsonReqeust, _ = json.Marshal(secretCollection)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", bytes.NewBuffer(jsonReqeust))

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretsRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Bad Path: Resources w/out SecretType

	secretCollection.Metadata.CollectionTotal = 1
	jsonReqeust, _ = json.Marshal(secretCollection)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", bytes.NewBuffer(jsonReqeust))

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretsRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Bad Path: Resources w/out name

	testSecret.SetSecretType("test-type")
	jsonReqeust, _ = json.Marshal(secretCollection)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", bytes.NewBuffer(jsonReqeust))

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretsRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// Good Path

	testSecret.SetName("test-name")
	jsonReqeust, _ = json.Marshal(secretCollection)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", bytes.NewBuffer(jsonReqeust))

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretsRequest(ctx, testRequest)
	if err != nil {
		t.Fail()
	}
}

func TestDecodeSecretActionRequestWrap(t *testing.T) {
	ctx := context.Background()

	// Bad Path: No Role

	// create test request to pass to handler
	testRequest, _ := http.NewRequest(http.MethodHead, "/test", nil)

	_, err := DecodeIDRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", nil)

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretActionRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	goodPath := func(_ http.ResponseWriter, request *http.Request) {
		_, err := DecodeSecretActionRequest(ctx, request)
		if err != nil {
			t.Errorf("Unexpected Error: %s", err)
		}
	}

	router := mux.NewRouter()
	router.HandleFunc("/test/{id}", goodPath).Methods(http.MethodPost)

	testSecretAction := new(actions.SecretAction)
	testSecretAction.Plaintext = "super-secret-plaintext"

	buf, errMarshal := json.Marshal(testSecretAction)
	if errMarshal != nil {
		t.Errorf("Unexpected Error: %s", errMarshal)
	}

	reader := bytes.NewBuffer(buf)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodPost, "/test/"+uuid.NewV4().String()+"?action=wrap", reader)

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, testRequest)
}

func TestDecodeSecretActionRequestUnwrap(t *testing.T) {
	ctx := context.Background()

	// Bad Path: No Role

	// create test request to pass to handler
	testRequest, _ := http.NewRequest(http.MethodHead, "/test", nil)

	_, err := DecodeIDRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodHead, "/test", nil)

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	_, err = DecodeSecretActionRequest(ctx, testRequest)
	if err == nil {
		t.Fail()
	}

	goodPath := func(_ http.ResponseWriter, request *http.Request) {
		_, err := DecodeSecretActionRequest(ctx, request)
		if err != nil {
			t.Errorf("Unexpected Error: %s", err)
		}
	}

	router := mux.NewRouter()
	router.HandleFunc("/test/{id}", goodPath).Methods(http.MethodPost)

	testSecretAction := new(actions.SecretAction)
	testSecretAction.Ciphertext = "super-secret-ciphertext"

	buf, errMarshal := json.Marshal(testSecretAction)
	if errMarshal != nil {
		t.Errorf("Unexpected Error: %s", errMarshal)
	}

	reader := bytes.NewBuffer(buf)

	// create test request to pass to handler
	testRequest, _ = http.NewRequest(http.MethodPost, "/test/"+uuid.NewV4().String()+"?action=unwrap", reader)

	testRequest.Header.Set(constants.BluemixUserRole, constants.RoleManager)

	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, testRequest)
}

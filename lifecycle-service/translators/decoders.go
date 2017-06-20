// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package translators

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"

	"context"

	corecomms "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-consts"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/collections"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/secrets"
)

// DecodeBaseRequest will decode request that come with only headers and parameters
func DecodeBaseRequest(_ context.Context, req *http.Request) (interface{}, error) {
	if errRoleCheck := roleCheck(req); errRoleCheck != nil {
		return nil, errRoleCheck
	}

	request := communications.NewBaseRequest()

	// Set the request headers
	setRequestHeaders(req, request)

	// Set Request Parameters
	if errSetParameters := setRequestParameters(req, request); errSetParameters != nil {
		return nil, errSetParameters
	}

	return request, nil
}

// DecodeSecretActionRequest will decode request that are called for by action
func DecodeSecretActionRequest(_ context.Context, req *http.Request) (interface{}, error) {
	if errRoleCheck := roleCheck(req); errRoleCheck != nil {
		return nil, errRoleCheck
	}

	request := corecomms.NewSecretActionRequest()

	// Set the request headers
	setRequestHeaders(req, request)

	// Set Request Parameters
	if errSetParameters := setRequestParameters(req, request); errSetParameters != nil {
		return nil, errSetParameters
	}

	if errExtractAction := extractIDAndValidateAction(req, request); errExtractAction != nil {
		return nil, errExtractAction
	}

	return request, nil
}

// DecodeIDRequest will decode request that come with IDs
func DecodeIDRequest(_ context.Context, req *http.Request) (interface{}, error) {
	if errRoleCheck := roleCheck(req); errRoleCheck != nil {
		return nil, errRoleCheck
	}

	request := communications.NewIDRequest()

	// Set Request Headers
	setRequestHeaders(req, request)

	// Set Request Parameters
	if errSetParameters := setRequestParameters(req, request); errSetParameters != nil {
		return nil, errSetParameters
	}

	id, errExtractID := extractID(req)
	if errExtractID != nil {
		return nil, errExtractID
	}

	request.ID = id

	return request, nil
}

// DecodeSecretRequest will decode request that come with single secret resources
func DecodeSecretRequest(_ context.Context, req *http.Request) (interface{}, error) {
	if errRoleCheck := roleCheck(req); errRoleCheck != nil {
		return nil, errRoleCheck
	}

	request := communications.NewSecretRequest()

	// Set Request Headers
	setRequestHeaders(req, request)

	// Set Request Parameters
	if errSetParameters := setRequestParameters(req, request); errSetParameters != nil {
		return nil, errSetParameters
	}

	if req.Body == nil {
		return nil, errors.New(http.StatusText(http.StatusBadRequest) + ": Request requires Body")
	}

	b, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, errors.New(http.StatusText(http.StatusBadRequest) + ": Request JSON Body")
	}
	reader := bytes.NewReader(b)

	// This Decode is the real one that we'll pass back to the service
	externalRequest := collections.NewSecretCollection()

	if err := json.NewDecoder(reader).Decode(externalRequest); err != nil {
		return nil, errors.New(http.StatusText(http.StatusBadRequest) + ": Request JSON Body: " + err.Error())
	}

	// Validate that the metadata was provided
	if int(externalRequest.GetTotal()) == 0 {
		return nil, fmt.Errorf(http.StatusText(http.StatusBadRequest) + ": Please provide a collection metadata total greater than zero")
	}

	collectionType := externalRequest.GetType()
	if collectionType == "" {
		return nil, fmt.Errorf(http.StatusText(http.StatusBadRequest)+": Please provide valid collection metadata type (%s)", collections.SecretMIME)
	} else if !supportedSecretCollectionTypes[collectionType] {
		return nil, fmt.Errorf(http.StatusText(http.StatusBadRequest)+": Collection Type %s, not supported", collectionType)
	}

	// Validate more than one resource was provided
	if len(externalRequest.Resources) == 0 {
		return nil, fmt.Errorf(http.StatusText(http.StatusBadRequest) + ": Please provide one or more resources")
	}

	// Validate collectionTotal matches number of resources provided
	numResources := len(externalRequest.Resources)
	numCollectionTotal := externalRequest.Metadata.CollectionTotal
	if int32(numResources) != numCollectionTotal {
		return nil, fmt.Errorf(http.StatusText(http.StatusBadRequest)+": Resource total %d, not equal to specified collectionTotal %d", numResources, numCollectionTotal)
	}

	secret := externalRequest.Resources[0]

	if secret.SecretType == "" {
		errResp := fmt.Errorf("%v: Please provide the secret type", http.StatusText(http.StatusBadRequest))
		return nil, errResp
	}

	if secret.Name == "" {
		errResp := fmt.Errorf("%v: Please provide the secret name", http.StatusText(http.StatusBadRequest))
		return nil, errResp
	}

	if secret.AuditTrail == nil {
		secret.AuditTrail = new(secrets.AuditTrail)
	}

	if secret.CryptoPeriod == nil {
		secret.CryptoPeriod = new(secrets.CryptoPeriod)
	}

	extr := true
	if reflect.ValueOf(secret.Extractable).IsNil() == true {
		secret.Extractable = &extr
	}

	secret.SetCreatedBy(req.Header.Get(constants.UserIDHeader))

	request.SetSecret(secret)

	return request, nil
}

// DecodeSecretsRequest will decode request that come with secret resources
func DecodeSecretsRequest(_ context.Context, req *http.Request) (interface{}, error) {
	if errRoleCheck := roleCheck(req); errRoleCheck != nil {
		return nil, errRoleCheck
	}

	request := communications.NewSecretsRequest()

	// Set Request Headers
	setRequestHeaders(req, request)

	// Set Request Parameters
	if errSetParameters := setRequestParameters(req, request); errSetParameters != nil {
		return nil, errSetParameters
	}

	if req.Body == nil {
		return nil, errors.New(http.StatusText(http.StatusBadRequest) + ": Request requires Body")
	}

	// We will read the request twice to avoid nil ptr error.  the first read is a throw-away, where we only want to get the
	// CollectionTotal value from the Metadata section of the request.  We will then use it to allocate the correct memory size so that the
	// second decode will work

	// in order to read twice because Decode will advance the buffer to the EOF, we will make a reader so we can have better control.
	b, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	reader := bytes.NewReader(b)

	// now we perform the first throw-away read to get the CollectionTotal
	collectionForMetaData := collections.NewSecretCollection()
	if err := json.NewDecoder(reader).Decode(collectionForMetaData); err != nil {
		return nil, fmt.Errorf(http.StatusText(http.StatusBadRequest)+": %s", err)
	}

	// Validate that the metadata was provided
	if int(collectionForMetaData.GetTotal()) == 0 {
		return nil, fmt.Errorf(http.StatusText(http.StatusBadRequest) + ": Please provide a collection metadata total greater than zero")
	}

	collectionType := collectionForMetaData.GetType()
	if collectionType == "" {
		return nil, fmt.Errorf(http.StatusText(http.StatusBadRequest)+": Please provide valid collection metadata type (%s)", collections.SecretMIME)
	} else if !supportedSecretCollectionTypes[collectionType] {
		return nil, fmt.Errorf(http.StatusText(http.StatusBadRequest)+": Collection Type %s, not supported", collectionType)
	}

	// Validate more than one resource was provided
	if len(collectionForMetaData.Resources) == 0 {
		return nil, fmt.Errorf(http.StatusText(http.StatusBadRequest) + ": Please provide one or more resources")
	}

	// Validate collectionTotal matches number of resources provided
	numResources := len(collectionForMetaData.Resources)
	numCollectionTotal := collectionForMetaData.Metadata.CollectionTotal
	if int32(numResources) != numCollectionTotal {
		return nil, fmt.Errorf(http.StatusText(http.StatusBadRequest)+": Resource total %d, not equal to specified collectionTotal %d", numResources, numCollectionTotal)
	}

	// This Decode is the real one that we'll pass back to the service
	externalRequest := collections.NewSecretCollection().SetTotal(collectionForMetaData.Metadata.CollectionTotal)
	reader.Seek(0, 0)

	if err := json.NewDecoder(reader).Decode(externalRequest); err != nil {
		return nil, err
	}

	request.Secrets = externalRequest.Resources

	//Verify that each secret has the required information
	for _, secret := range request.Secrets {
		if secret.SecretType == "" {
			errResp := fmt.Errorf("%v: Please provide the secret type", http.StatusText(http.StatusBadRequest))
			return nil, errResp
		}

		if secret.Name == "" {
			errResp := fmt.Errorf("%v: Please provide the secret name", http.StatusText(http.StatusBadRequest))
			return nil, errResp
		}

		secret.SetCreatedBy(req.Header.Get(constants.UserIDHeader))
	}
	return request, nil
}

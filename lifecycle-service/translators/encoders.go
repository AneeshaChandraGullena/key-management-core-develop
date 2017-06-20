// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package translators

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"context"

	kithttp "github.com/go-kit/kit/transport/http"

	corecomms "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/communications"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/translators/crn"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/transport/routes"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-consts"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/collections"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
)

// EncodeGenericResponse is used to
func EncodeGenericResponse(ctx context.Context, respWriter http.ResponseWriter, response interface{}) error {
	method := ctx.Value(kithttp.ContextKeyRequestMethod).(string)
	path := ctx.Value(kithttp.ContextKeyRequestPath).(string)

	// TODO: In the future we want head and list to have the same return type
	// and just check the method to determine what should be returned. This can be done now
	// that we have more information in the context. TSC May 22, 2017
	switch {
	case method == http.MethodHead:
		// used to encode responses for head
		if numberResponse, ok := response.(*communications.NumberResponse); ok {
			respWriter.Header().Set(constants.ContentTypeHeader, constants.AppJSONMime+"; charset=utf-8")

			respWriter.Header().Add(constants.KeyTotalForSpaceHeader, strconv.Itoa(int(numberResponse.Number)))
			respWriter.WriteHeader(http.StatusNoContent)

			return nil
		}
		return fmt.Errorf("Requires type *communications.NumberResponse, received %T", response)
	case method == http.MethodGet || method == http.MethodDelete || (method == http.MethodPost && !strings.Contains(path, routes.APIv2SecretsID)):
		// used encode responses for get, list, create and delete
		if secretsResponse, ok := response.(*communications.SecretsResponse); ok {
			respWriter.Header().Set(constants.ContentTypeHeader, constants.AppJSONMime+"; charset=utf-8")

			collectionResponse := collections.NewSecretCollection()
			for _, secret := range secretsResponse.Secrets {
				if crname, err := crn.GetCRN(ctx, secret.ID); err == nil {
					secret.Crn = crname
				}
				collectionResponse.Append(secret)
			}

			if method == http.MethodDelete && collectionResponse.GetTotal() == 0 {
				respWriter.WriteHeader(http.StatusNoContent)
				return nil
			}

			respWriter.Header().Add(constants.KeyTotalForSpaceHeader, strconv.Itoa(int(collectionResponse.GetTotal())))

			if method == http.MethodPost {
				respWriter.WriteHeader(http.StatusCreated)
			}

			return json.NewEncoder(respWriter).Encode(collectionResponse)
		}
		return fmt.Errorf("Requires type *communications.SecretsResponse, received %T", response)
	case method == http.MethodPost && strings.Contains(path, routes.APIv2SecretsID):
		// used to encode responses for action
		if actionResponse, ok := response.(*corecomms.SecretActionResponse); ok {
			respWriter.Header().Set(constants.ContentTypeHeader, constants.AppJSONMime+"; charset=utf-8")

			return json.NewEncoder(respWriter).Encode(actionResponse)
		}
		return fmt.Errorf("Requires type *corecomms.SecretActionResponse, received %T", response)
	default:
		return fmt.Errorf(http.StatusText(http.StatusBadRequest)+": Method %s is not supported", method)
	}
}

// EncodeError will encode all errors that are returned.
// TODO: we need a way to mask some or all errors. we can either do it here or in the models package.
// The models package maybe a better place than here as we already have the Converter there. TSC 2-9-17
func EncodeError(_ context.Context, err error, respWriter http.ResponseWriter) {
	errorResponse := collections.NewErrorCollection().Append(err)

	// Since the collection was just created, there is no way for an error to be returned here
	// since there will always be at least 1 error type in the error collection.
	member, _ := errorResponse.GetMember(0)
	respWriter.WriteHeader(int(member.StatusCode))
	json.NewEncoder(respWriter).Encode(errorResponse)
}

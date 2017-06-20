// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package translators

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"

	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/actions"
	corecomms "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/communications"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/transport/routes"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-consts"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/collections"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
)

var (
	// ErrBadRouting is returned when an expected path variable is missing.
	// It always indicates programmer error.
	ErrBadRouting = errors.New("inconsistent mapping between route and handler (programmer error)")

	supportedSecretCollectionTypes = map[collections.CollectionType]bool{
		collections.SecretMIME: true,
	}

	// Map role's from least to greatest privilege. starts at one so that if an unknown role or no role is passed in, it will return 0 and therefore be below all other roles.
	roleWeight = map[string]int{
		constants.RoleAuditor:   1,
		constants.RoleDeveloper: 2,
		constants.RoleManager:   3,
	}

	methodToLeastRequiredRole = map[string]string{
		http.MethodHead:   constants.RoleAuditor,
		http.MethodPost:   constants.RoleDeveloper,
		http.MethodGet:    constants.RoleDeveloper,
		http.MethodDelete: constants.RoleManager,
	}
)

func setRequestParameters(req *http.Request, request communications.Request) error {
	requestParameters := request.GetParameters()

	query := req.URL.Query()

	limitStr := query.Get("limit")
	if limitStr == "" {
		requestParameters.Limit = 20
	} else {
		limit, limitErr := strconv.Atoi(limitStr)
		if limitErr != nil {
			return limitErr
		}

		requestParameters.Limit = int32(limit)
	}

	offsetStr := query.Get("offset")
	if offsetStr == "" {
		requestParameters.Offset = 0
	} else {
		offset, offsetErr := strconv.Atoi(offsetStr)
		if offsetErr != nil {
			return offsetErr
		}
		requestParameters.Offset = int32(offset)
	}

	// If not specified as a query parameter, default to NOT include resource since it will include payload
	if strings.Contains(strings.ToLower(req.Header.Get(constants.Prefer)), constants.Representation) {
		requestParameters.IncludeResource = true
	} else {
		requestParameters.IncludeResource = false
	}

	return nil
}

func setRequestHeaders(req *http.Request, request communications.Request) {
	requestHeaders := request.GetHeaders()
	requestHeaders.Authorization = req.Header.Get(constants.AuthorizationHeader)
	requestHeaders.BluemixOrg = req.Header.Get(constants.BluemixOrgHeader)
	requestHeaders.BluemixSpace = req.Header.Get(constants.BluemixSpaceHeader)
	requestHeaders.CorrelationID = req.Header.Get(constants.CorrelationIDHeader)
	requestHeaders.UserID = req.Header.Get(constants.UserIDHeader)
}

func roleCheck(req *http.Request) error {
	if roleWeight[req.Header.Get(constants.BluemixUserRole)] < roleWeight[methodToLeastRequiredRole[req.Method]] {
		return errors.New(http.StatusText(http.StatusForbidden) + ": User's role does not provide access to this resource")
	}
	return nil
}

func extractID(req *http.Request) (string, error) {
	vars := mux.Vars(req)
	if id, ok := vars["id"]; ok {
		if _, err := uuid.FromString(id); err != nil {
			return "", errors.New(http.StatusText(http.StatusBadRequest) + ": malformed UUID.")
		}
		return id, nil
	}
	return "", ErrBadRouting
}

func jsonDecodeSecretAction(req *http.Request) (*actions.SecretAction, error) {
	secretAction := new(actions.SecretAction)

	if err := json.NewDecoder(req.Body).Decode(secretAction); err != nil {
		return nil, fmt.Errorf(http.StatusText(http.StatusBadRequest)+": Request JSON Body: %s", err)
	}

	return secretAction, nil
}

func validateWrapAction(req *http.Request, request *corecomms.SecretActionRequest) error {
	wrapAction, errJSONDecode := jsonDecodeSecretAction(req)
	if errJSONDecode != nil {
		return errJSONDecode
	}

	if len(wrapAction.Ciphertext) != 0 {
		return errors.New(http.StatusText(http.StatusBadRequest) + ": Wrap request has no field, Ciphertext")
	}

	request.SecretAction = wrapAction
	return nil
}

func validateUnwrapAction(req *http.Request, request *corecomms.SecretActionRequest) error {
	unwrapAction, errJSONDecode := jsonDecodeSecretAction(req)
	if errJSONDecode != nil {
		return errJSONDecode
	}

	if len(unwrapAction.Ciphertext) == 0 {
		return errors.New(http.StatusText(http.StatusBadRequest) + ": Unwrap request requires ciphertext field")
	}

	if len(unwrapAction.Plaintext) != 0 {
		return errors.New(http.StatusText(http.StatusBadRequest) + ": UnWrap request has no field, Plaintext")
	}

	request.SecretAction = unwrapAction
	return nil
}

func extractIDAndValidateAction(req *http.Request, request *corecomms.SecretActionRequest) error {
	query := req.URL.Query()

	id, errExtractID := extractID(req)
	if errExtractID != nil {
		return errExtractID
	}

	request.ID = id

	action := strings.ToLower(query.Get("action"))

	// TODO: In the future this, or parts of this, maybe should be moved somewhere else
	// that owns actions. TSC May 22, 2017
	switch action {
	case "wrap":
		return validateWrapAction(req, request)
	case "unwrap":
		return validateUnwrapAction(req, request)
	default:
		return fmt.Errorf(http.StatusText(http.StatusBadRequest)+": %s is not a supported action", action)
	}
}

// validate the mime type that is passed in from the Content-Type Header
func validateMIMETypeBasedOnRoute(req *http.Request) error {
	if strings.Contains(req.URL.Path, routes.APIv2Keys) {
		if reqContentType, expectedContentType := req.Header.Get(constants.ContentTypeHeader), string(corecomms.Key); strings.Compare(reqContentType, expectedContentType) != 0 {
			return errors.New(http.StatusText(http.StatusBadRequest) + ": invalid content-type provided")
		}
	}

	if reqContentType, expectedContentType := req.Header.Get(constants.ContentTypeHeader), string(corecomms.Secret); strings.Compare(reqContentType, expectedContentType) != 0 {
		return errors.New(http.StatusText(http.StatusBadRequest) + ": invalid content-type provided")
	}

	return nil
}

// © Copyright 2016 IBM Corp. Licensed Materials – Property of IBM.

package client

import (
	"encoding/json"
	"net/http"

	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/secrets"
)

//Barbican order states
const (
	statePending = "PENDING"
	stateActive  = "ACTIVE"
	stateError   = "ERROR"
)

// OrderMeta is the stucture use to house the barbican Order meta data for post order
type OrderMeta struct {
	Name               string `json:"name"`
	Algorithm          string `json:"algorithm,omitempty"`
	BitLength          int32  `json:"bit_length"`
	Mode               string `json:"mode,omitempty"`
	PayloadContentType string `json:"payload_content_type"`
}

// PostOrderRequest is the main structure for post orders
type PostOrderRequest struct {
	Type string     `json:"type"`
	Meta *OrderMeta `json:"meta"`
}

// postOrderResponse is the main structure for post order responses
type postOrderResponse struct {
	Ref string `json:"order_ref"`
}

// CheckOrderResponse is a struct used to check the state of an order
type CheckOrderResponse struct {
	SecretRef string
	KeyStatus secrets.KeyStates
}

type internalOrderResponse struct {
	//Internals not exposed to other packages.
	//Should be set up by barbican client then exposed
	//by SecretRef and KeyStatus fields in CheckOrderResponse
	BarbicanRef         string `json:"secret_ref"`
	BarbicanKeyStatus   string `json:"status"`
	BarbicanErrorReason string `json:"error_reason"`
	BarbicanErrorCode   string `json:"error_status_code"`
}

func decoderPostOrderResponse(response *http.Response) (ref string, err error) {
	if response.StatusCode != http.StatusAccepted {
		errorResponse := new(ErrorResponse)
		err := json.NewDecoder(response.Body).Decode(errorResponse)
		if err != nil {
			return "", err
		}

		return "", errorResponse
	}

	formattedResponse := new(postOrderResponse)
	errJSON := json.NewDecoder(response.Body).Decode(formattedResponse)
	if errJSON != nil {
		return "", errJSON
	}

	return parseRef(formattedResponse.Ref), nil
}

func decoderCheckOrderResponse(response *http.Response) (*CheckOrderResponse, error) {
	if response.StatusCode != http.StatusOK {
		errorResponse := new(ErrorResponse)
		err := json.NewDecoder(response.Body).Decode(errorResponse)
		if err != nil {
			return nil, err
		}

		return nil, errorResponse
	}

	internalResponse := new(internalOrderResponse)
	err := json.NewDecoder(response.Body).Decode(internalResponse)
	if err != nil {
		return nil, err
	}

	formattedResponse := new(CheckOrderResponse)
	if internalResponse.BarbicanKeyStatus == stateActive {
		formattedResponse.SecretRef = parseRef(internalResponse.BarbicanRef)
		formattedResponse.KeyStatus = secrets.Activation
	} else if internalResponse.BarbicanKeyStatus == stateError {
		formattedResponse.KeyStatus = secrets.GenerationError
	} else {
		formattedResponse.KeyStatus = secrets.Preactivation
	}

	return formattedResponse, nil
}

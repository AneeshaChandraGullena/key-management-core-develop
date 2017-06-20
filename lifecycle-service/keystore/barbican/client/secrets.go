// © Copyright 2016 IBM Corp. Licensed Materials – Property of IBM.

package client

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.ibm.com/Alchemy-Key-Protect/kp-go-consts"
)

// PostSecretRequest is the main structure for post secret requests
type PostSecretRequest struct {
	Name               string `json:"name"`
	Payload            string `json:"payload"`
	PayloadContentType string `json:"payload_content_type"`
}

// postSecretResponse is the main structure for post secret responses
type postSecretResponse struct {
	Ref string `json:"secret_ref"`
}

func decoderPostSecretResponse(response *http.Response) (refs string, err error) {
	body, errBody := ioutil.ReadAll(response.Body)
	if errBody != nil {
		return "", errBody
	}

	if response.StatusCode != http.StatusCreated {
		errorResponse := new(ErrorResponse)
		err := json.Unmarshal(body, errorResponse)
		if err != nil {
			errorResponse = decodeError(body)
		}
		return "", errorResponse
	}

	formattedResponse := new(postSecretResponse)
	errJSON := json.Unmarshal(body, formattedResponse)
	if errJSON != nil {
		return "", errJSON
	}

	return parseRef(formattedResponse.Ref), nil
}

func decodeGetPayloadResponse(response *http.Response, contentType string) (payload string, err error) {
	body, errBody := ioutil.ReadAll(response.Body)
	if errBody != nil {
		return "", errBody
	}

	if response.StatusCode != http.StatusOK {
		errorResponse := new(ErrorResponse)
		err := json.Unmarshal(body, errorResponse)
		if err != nil {
			errorResponse = decodeError(body)
		}

		return "", errorResponse
	}

	if contentType == constants.OctetStreamMime {
		return base64.StdEncoding.EncodeToString(body), nil
	}

	return string(body), nil
}

type kpMiddlewareError struct {
	Message string `json:"message"`
	Title   string `json:"title"`
}

/*
Temporary handler for errors given by barbican UAA middleware
TODO Fix the barbican UAA middleware to return a JSON object.
TODO Once middleware is fixed remove this function and use
golang marshaller
*/
func decodeError(body []byte) *ErrorResponse {
	errorResponse := new(ErrorResponse)
	tmpResponse := new(kpMiddlewareError)

	err := json.Unmarshal(body, tmpResponse)
	if err != nil {
		errorResponse.Message = http.StatusText(http.StatusInternalServerError)
		errorResponse.Title = "Something went wrong."
		return errorResponse
	}

	//Need to remove new lines and <br> from the message.
	tmpResponse.Message = strings.TrimSpace(tmpResponse.Message)
	tmpResponse.Message = strings.Replace(tmpResponse.Message, "<br>", "", -1)
	tmpResponse.Message = strings.Replace(tmpResponse.Message, "<br />", "", -1)

	errorResponse.Title = tmpResponse.Title
	errorResponse.Message = tmpResponse.Message
	return errorResponse
}

// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package communications

import (
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/actions"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
)

// SecretActionRequest are used for all requests for actions on secrets
type SecretActionRequest struct {
	*communications.BaseRequest
	*actions.SecretAction
	ID string
}

// NewSecretActionRequest creates a new SecretActionRequest
func NewSecretActionRequest() *SecretActionRequest {
	request := new(SecretActionRequest)
	request.BaseRequest = communications.NewBaseRequest()
	request.SecretAction = new(actions.SecretAction)
	return request
}

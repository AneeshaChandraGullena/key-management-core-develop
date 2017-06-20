// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package communications

import "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/actions"

// SecretActionResponse are used for all responses for actions on secrets
type SecretActionResponse struct {
	*actions.SecretAction
}

// GetBody is a method get the response body as an empty interface
func (response *SecretActionRequest) GetBody() interface{} {
	return response.SecretAction
}

// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package definitions

import (
	"context"

	corecomms "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
)

// Service is the main interface for Secret Service
type Service interface {
	Post(context.Context, *communications.SecretRequest) (*communications.SecretsResponse, error)
	Actions(context.Context, *corecomms.SecretActionRequest) (*corecomms.SecretActionResponse, error)
	Get(context.Context, *communications.IDRequest) (*communications.SecretsResponse, error)
	Head(context.Context, *communications.BaseRequest) (*communications.NumberResponse, error)
	List(context.Context, *communications.BaseRequest) (*communications.SecretsResponse, error)
	Delete(context.Context, *communications.IDRequest) (*communications.SecretsResponse, error)
}

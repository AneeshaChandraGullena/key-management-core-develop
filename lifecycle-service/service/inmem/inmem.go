// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package inmem

import (
	"errors"
	"sync"

	svcDef "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/definitions"
	corecomms "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/secrets"

	"context"

	uuid "github.com/satori/go.uuid"
)

var (
	// ErrAlreadyExists notifies caller on the POST when a secret already exists in the in-memory map
	ErrAlreadyExists = errors.New("already exists")

	// ErrNotFound notifies callers on the GET when secret cannot be found
	ErrNotFound = errors.New("not found")
)

type inmemService struct {
	sync.RWMutex
	data map[string]*secrets.Secret
}

// Service creates a new service that uses an in memory db
func Service() svcDef.Service {
	return &inmemService{
		data: map[string]*secrets.Secret{},
	}
}

func (svc *inmemService) Post(ctx context.Context, request *communications.SecretRequest) (*communications.SecretsResponse, error) {
	svc.Lock()
	defer svc.Unlock()

	secret := request.Secret

	id := uuid.NewV4().String()
	secret.ID = id
	svc.data[secret.ID] = secret

	includeResource := request.GetParameters().IncludeResource

	response := communications.NewSecretsResponse()

	if includeResource == true {
		response.AppendSecret(secret)
	} else {
		minimalReturnSecret := secrets.NewSecret().SetID(id).SetName(secret.Name)
		response.AppendSecret(minimalReturnSecret)
	}

	return response, nil
}

func (svc *inmemService) Actions(ctx context.Context, request *corecomms.SecretActionRequest) (*corecomms.SecretActionResponse, error) {
	return nil, nil
}

func (svc *inmemService) Get(ctx context.Context, request *communications.IDRequest) (*communications.SecretsResponse, error) {
	svc.RLock()
	defer svc.RUnlock()

	id := request.ID

	secret, ok := svc.data[id]
	if !ok {
		return nil, ErrNotFound
	}

	response := communications.NewSecretsResponse()

	return response.AppendSecret(secret), nil
}

func (svc *inmemService) Head(ctx context.Context, request *communications.BaseRequest) (*communications.NumberResponse, error) {
	svc.RLock()
	defer svc.RUnlock()

	response := communications.NewNumberResponse()

	response.Number = int32(len(svc.data))

	return response, nil
}

func intMin(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func (svc *inmemService) List(ctx context.Context, request *communications.BaseRequest) (*communications.SecretsResponse, error) {
	svc.RLock()
	defer svc.RUnlock()

	parameters := request.GetParameters()
	limit := int(parameters.Limit)
	offset := int(parameters.Offset)

	var secrets []*secrets.Secret

	i := 0
	for _, secret := range svc.data {
		if i > offset && i < intMin(offset+limit, len(svc.data)) {
			secrets = append(secrets, secret)
		}
		i++
	}

	response := communications.NewSecretsResponse()
	response.SetSecrets(secrets)

	return response, nil
}

func (svc *inmemService) Delete(ctx context.Context, request *communications.IDRequest) (*communications.SecretsResponse, error) {
	svc.RLock()
	defer svc.RUnlock()

	id := request.ID

	secret, ok := svc.data[id]
	if !ok {
		return nil, ErrNotFound
	}

	includeResource := request.GetParameters().IncludeResource

	response := communications.NewSecretsResponse()

	if includeResource {
		response.AppendSecret(secret)
	}

	delete(svc.data, id)

	return response, nil
}

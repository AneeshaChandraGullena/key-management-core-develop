// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package mock

import (
	"errors"
	"net/http"
	"sync"

	"github.com/go-kit/kit/log"
	uuid "github.com/satori/go.uuid"

	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/definitions"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/transactions"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/secrets"
)

var (
	secretStore map[string]*simpleSecret

	// ErrNotFound notifies callers on the GET when secret cannot be found
	ErrNotFound = errors.New(http.StatusText(http.StatusNotFound) + ": Unable to find secret")
)

type simpleSecret struct {
	payload string
	state   secrets.KeyStates
}

func init() {
	secretStore = make(map[string]*simpleSecret)
}

type inmemKeystore struct {
	sync.RWMutex
	headers *communications.Headers
}

func extractBluemixOrgSpace(s *inmemKeystore) (org, space string, err error) {
	headers := s.headers
	if headers == nil {
		err = errors.New(http.StatusText(http.StatusBadRequest) + ": Headers required")
		return
	}

	space = headers.BluemixSpace
	if space == "" {
		err = errors.New(http.StatusText(http.StatusBadRequest) + ": Header Bluemix-Space required")
		return
	}

	org = headers.BluemixOrg
	if org == "" {
		err = errors.New(http.StatusText(http.StatusBadRequest) + ": Header Bluemix-Org required")
		return
	}

	return
}

//GetPayload : Get a payload with the given keyprotect ID
func (s *inmemKeystore) GetPayload(keyprotectID string) (string, secrets.KeyStates, error) {
	_, _, extractErr := extractBluemixOrgSpace(s)
	if extractErr != nil {
		return "", secrets.Destroyed, extractErr
	}

	if _, ok := secretStore[keyprotectID]; !ok {
		return "", secrets.Destroyed, ErrNotFound
	}

	payload := secretStore[keyprotectID].payload

	return payload, secrets.Activation, nil
}

// CreateSecret creates a secret using inside the barbican user defined metadata table
func (s *inmemKeystore) CreateSecret(secret *secrets.Secret, createTx *transactions.Transaction) (string, error) {
	_, _, extractErr := extractBluemixOrgSpace(s)
	if extractErr != nil {
		return "", extractErr
	}

	payloadLength := len(secret.Payload)
	if payloadLength == 0 {
		secret.SetPayload(generateSecret())
	}

	s.Lock()
	defer s.Unlock()

	id := uuid.NewV4().String()

	simpleSecret := &simpleSecret{
		payload: secret.Payload,
		state:   secret.State,
	}

	secretStore[id] = simpleSecret

	return id, nil
}

func generateSecret() string {
	return uuid.NewV4().String()
}

// DeleteSecret Given a keyprotect ID. Delete the user's secret.
func (s *inmemKeystore) DeleteSecret(keyprotectID string, createTx *transactions.Transaction) error {
	_, _, extractErr := extractBluemixOrgSpace(s)
	if extractErr != nil {
		return extractErr
	}

	s.RLock()
	defer s.RUnlock()

	if _, ok := secretStore[keyprotectID]; !ok {
		return ErrNotFound
	}

	delete(secretStore, keyprotectID)

	return nil
}

// CheckSecret: Given a keyprotect id, is the secret active?
func (s *inmemKeystore) CheckSecret(keyprotectID string) (secrets.KeyStates, error) {
	if _, ok := secretStore[keyprotectID]; !ok {
		return secrets.Destroyed, ErrNotFound
	}

	state := secretStore[keyprotectID].state

	return state, nil
}

// NewMockKeystore will return a new barbican Keystore
func NewMockKeystore(auth *communications.Headers, logger log.Logger) definitions.Keystore {
	s := new(inmemKeystore)
	s.headers = auth
	return s
}

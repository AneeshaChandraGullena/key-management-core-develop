// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package definitions

import (
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/transactions"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/secrets"
)

// Keystore is the interface for all keystore plugins
type Keystore interface {
	GetPayload(keyprotectID string) (string, secrets.KeyStates, error)
	CheckSecret(keyprotectID string) (secrets.KeyStates, error)
	CreateSecret(secret *secrets.Secret, createTx *transactions.Transaction) (string, error)
	DeleteSecret(keyprotectID string, createTx *transactions.Transaction) error
}

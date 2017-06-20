// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package keystore

import (
	"errors"

	"github.com/go-kit/kit/log"

	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/definitions"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/keystore/barbican"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/keystore/mock"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
)

// Type is the type of backend end strategies that are supported
// currently only support barbican
type Type int

const (
	// Barbican Keystore Type
	Barbican Type = iota

	// Mock for mock Keystore for local testing
	Mock
)

// NewKeystore will return the selected Keystore based on type, authorization needed
// for the Keystore is also required to be based in on creation
func NewKeystore(keystoreType Type, auth *communications.Headers, logger log.Logger) (definitions.Keystore, error) {
	switch keystoreType {
	case Barbican:
		return barbican.NewBarbicanKeystore(auth, logger), nil
	case Mock:
		return mock.NewMockKeystore(auth, logger), nil
	default:
		return nil, errors.New("Type not supported")
	}
}

// © Copyright 2016 IBM Corp. Licensed Materials – Property of IBM.

package transactions

//===========================
// Leaf: hsmCreateSecret
//===========================

// RollbackHsmCreateSecret is a function pointer to the inverse function of a successfull HSM secret creation, which should be the barbican delete function.
// If that delete function signature changes, this type needs to change, as well.
type RollbackHsmCreateSecret func(barbicanSecretRef string) error

// HsmCreateRollbackValues holds information for the rollback function to call and all of its required input parameters
type HsmCreateRollbackValues struct {
	execute   RollbackHsmCreateSecret
	secretRef string
}

// NewHsmCreateSecretRollback creates a new rollback for metadata creation failures
func NewHsmCreateSecretRollback(inverseFunction RollbackHsmCreateSecret, secretRef string) HsmCreateRollbackValues {
	return HsmCreateRollbackValues{
		execute:   inverseFunction,
		secretRef: secretRef,
	}
}

// Clean performs the cleanup operation for metadata creation
func (rollback HsmCreateRollbackValues) Clean() error {
	return rollback.execute(rollback.secretRef)
}

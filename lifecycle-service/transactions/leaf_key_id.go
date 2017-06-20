// © Copyright 2016 IBM Corp. Licensed Materials – Property of IBM.

package transactions

//===========================
// Leaf: Metadata
//===========================

// RollbackKeyID is a function pointer to the inverse function of a successfull key ID creation, which should be the deleteID function.
// If that delete function signature changes, this type needs to change, as well.
type RollbackKeyID func(keyProtectID string, space string, org string, i interface{}) error

// KeyIDValues holds information for the rollback function to call and all of its required input parameters
type KeyIDValues struct {
	execute      RollbackKeyID
	keyProtectID string
	space        string
	org          string
	i            interface{}
}

// NewKeyIDRollback creates a new rollback for KeyID creation failures
func NewKeyIDRollback(inverseFunction RollbackKeyID, keyID string, space string, org string, i interface{}) KeyIDValues {
	return KeyIDValues{
		execute:      inverseFunction,
		keyProtectID: keyID,
		space:        space,
		org:          org,
		i:            i,
	}
}

// Clean performs the cleanup operation for metadata creation
func (rollback KeyIDValues) Clean() error {
	return rollback.execute(rollback.keyProtectID, rollback.space, rollback.org, rollback.i)
}

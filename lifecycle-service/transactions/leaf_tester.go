// © Copyright 2016 IBM Corp. Licensed Materials – Property of IBM.

package transactions

//===========================
// Leaf: sillyRollback:
// for testing only
//===========================
type sillyRollback func(parm1 int, parm2 string) error

type sillyRollbackValues struct {
	execute sillyRollback
	parm1   int
	parm2   string
}

// newMetadataRollback creates a new rollback for metadata creation failures
func newSillyRollback(inverseFunction sillyRollback, parm1 int, parm2 string) sillyRollbackValues {
	return sillyRollbackValues{
		execute: inverseFunction,
		parm1:   parm1,
		parm2:   parm2,
	}
}

// Clean performs the cleanup operation for metadata creation
func (rollback sillyRollbackValues) Clean() error {
	return rollback.execute(rollback.parm1, rollback.parm2)
}

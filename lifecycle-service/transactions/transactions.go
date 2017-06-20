// © Copyright 2016 IBM Corp. Licensed Materials – Property of IBM.

package transactions

// Cleaner defines what methods must be done to cleanup a transaction.  This follows the composite pattern and acts
// as the base class designed by the "component"
type Cleaner interface {
	Clean() error
}

// Transaction defines all of the operations needed to rollback if the transaction fails.  It acts as the "Composite" in the composite pattern
// The slice holds all of the operations that can be executed if cleanup is needed
// completed designates if the transaction completed or not.
type Transaction struct {
	RollbackOperations []Cleaner
	Completed          bool
}

// Transactioner defines the methods needed to operate on the composite object.
type Transactioner interface {
	Add(operation Cleaner)
	Complete()
}

// NewTransaction creates a new transaction.  It should be used to start a transaction
func NewTransaction() Transaction {
	return Transaction{
		RollbackOperations: make([]Cleaner, 0),
		Completed:          false,
	}
}

// Add implements adding an operation for rollback.  It prepends the new operation so that when Clean is called, functions are invoked in reverse order.
// For instnace, if you run funciton A, B, C;  then Clean will run C(inverse), B(inverse), A(inverse) functions in the exact opposite order
func (tr *Transaction) Add(operation Cleaner) {
	tr.RollbackOperations = append([]Cleaner{operation}, tr.RollbackOperations...)
}

// Complete indicates that the Transaction is done and cleans things up
func (tr *Transaction) Complete() {
	tr.Completed = true
	tr.RollbackOperations = tr.RollbackOperations[:0] //TODO hopefully, not a memory leak
}

// Clean goes thru all of the rollback operations and attempts to cleanup the unfinished transaction
func (tr *Transaction) Clean() error {
	if tr.Completed == true {
		panic("cannot rollback a completed transaction")
	}
	for _, operation := range tr.RollbackOperations {
		err := operation.Clean()
		if err != nil {
			return err
		}
	}
	return nil
}

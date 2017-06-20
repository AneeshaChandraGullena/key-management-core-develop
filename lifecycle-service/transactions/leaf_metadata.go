// © Copyright 2016 IBM Corp. Licensed Materials – Property of IBM.

package transactions

import (
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/secrets"
)

//===========================
// Leaf: Metadata
// Note: At this time, barbican doesn't let users delete the metadata separate from the key, so
// there is no real inverse of creating the metadata table.
//===========================

// RollbackMetadata is a function pointer to the inverse function of a successfull metadata creation, which should be the delete metadata function.
// If that delete function signature changes, this type needs to change, as well.
type RollbackMetadata func(metadata *secrets.Secret) error

// MetadataValues holds information for the rollback function to call and all of its required input parameters
type MetadataValues struct {
	execute  RollbackMetadata
	metadata *secrets.Secret
}

// NewMetadataRollback creates a new rollback for metadata creation failures
func NewMetadataRollback(inverseFunction RollbackMetadata, metadata *secrets.Secret) MetadataValues {
	return MetadataValues{
		execute:  inverseFunction,
		metadata: metadata,
	}
}

// Clean performs the cleanup operation for metadata creation
func (rollback MetadataValues) Clean() error {
	return rollback.execute(rollback.metadata)
}

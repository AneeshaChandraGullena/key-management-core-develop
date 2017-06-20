// © Copyright 2016 IBM Corp. Licensed Materials – Property of IBM.

package transactions

import (
	"context"

	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
)

//===========================
// Leaf: deletemetadata
// Note: Barbican cannot undelete a secret so there is no rollback for a failed delete on barbican
//===========================

// RollbackCreateMetadata is a function pointer to the inverse function of a successfull metadata delete, which should be the create metadata function.
// If that create function signature changes, this type needs to change, as well.
type RollbackCreateMetadata func(ctx context.Context, req communications.Request) (communications.Response, error)

// MetadataCreateValues holds information for the rollback function to call and all of its required input parameters
type MetadataCreateValues struct {
	execute RollbackCreateMetadata
	ctx     context.Context
	req     communications.Request
}

// NewMetadataCreateRollback creates a new rollback for metadata creation failures
func NewMetadataCreateRollback(inverseFunction RollbackCreateMetadata, ctx context.Context, req communications.Request) MetadataCreateValues {
	return MetadataCreateValues{
		execute: inverseFunction,
		ctx:     ctx,
		req:     req,
	}
}

// Clean performs the cleanup operation for metadata creation
func (rollback MetadataCreateValues) Clean() error {
	// TODO: Here run rollback execute THEN just return error
	_, errDbResponse := rollback.execute(rollback.ctx, rollback.req)
	if errDbResponse != nil {
		return errDbResponse
	}

	return nil
}

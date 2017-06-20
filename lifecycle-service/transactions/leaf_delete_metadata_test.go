// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package transactions

import (
	"errors"
	"testing"

	"context"

	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
)

func TestMetadataCreateRollback(t *testing.T) {
	ctx := context.Background()

	var testError error
	f := func(ctx context.Context, req communications.Request) (communications.Response, error) {
		return nil, testError
	}

	rollback := NewMetadataCreateRollback(f, ctx, communications.NewBaseRequest())

	if err := rollback.Clean(); err != nil {
		t.Fail()
	}

	testError = errors.New("test-error")

	if err := rollback.Clean(); err.Error() != testError.Error() {
		t.Fail()
	}
}

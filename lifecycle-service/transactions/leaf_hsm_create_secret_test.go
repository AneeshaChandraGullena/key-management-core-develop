// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package transactions

import (
	"errors"
	"testing"
)

func TestHsmCreateSecretRollback(t *testing.T) {
	var testError error
	f := func(barbicanSecretRef string) error {
		return testError
	}

	rollback := NewHsmCreateSecretRollback(f, "test-ref")

	if err := rollback.Clean(); err != nil {
		t.Fail()
	}

	testError = errors.New("test-error")

	if err := rollback.Clean(); err.Error() != testError.Error() {
		t.Fail()
	}
}

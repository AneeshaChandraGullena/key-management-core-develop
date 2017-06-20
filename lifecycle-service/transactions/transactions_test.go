// © Copyright 2016 IBM Corp. Licensed Materials – Property of IBM.

package transactions

import (
	"fmt"
	"testing"

	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/secrets"
)

func TestNewTransaction(t *testing.T) {
	createTransaction := NewTransaction()
	if createTransaction.Completed != false {
		t.Errorf("NewTransaction() => %v want %v", createTransaction.Completed, false)
	}

	if len(createTransaction.RollbackOperations) != 0 {
		t.Errorf("NewTransaction().RollbackOperations => %v want %v", len(createTransaction.RollbackOperations), 0)
	}
}

func TestCompleteTransaction(t *testing.T) {
	createTransaction := NewTransaction()

	createTransaction.Complete()

	if createTransaction.Completed != true {
		t.Errorf("NewTransaction() => %v want %v", createTransaction.Completed, true)
	}

	if len(createTransaction.RollbackOperations) != 0 {
		t.Errorf("NewTransaction().RollbackOperations => %v want %v", len(createTransaction.RollbackOperations), 0)
	}
}

func TestIllegalCleanup(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("should have panic since Cleanup not allowed after transaction marked completed")
		}
	}()

	createTransaction := NewTransaction()

	createTransaction.Complete()
	if error := createTransaction.Clean(); error != nil {
		t.Errorf("no error expected")
	}
}

func TestAddTransactionForMetadataType(t *testing.T) {
	// setup some test scenarios
	var testCases = []struct {
		name         string
		expectError  bool
		testFunction RollbackMetadata
	}{
		{"success", false, func(metadata *secrets.Secret) error {
			return nil
		}},
		{"failure", true, func(metadata *secrets.Secret) error {
			return fmt.Errorf("dummy error %v", true)
		}},
	}

	for _, scenario := range testCases {
		createTransaction := NewTransaction()

		testMeta := NewMetadataRollback(scenario.testFunction, secrets.NewSecret())
		createTransaction.Add(testMeta)
		if len(createTransaction.RollbackOperations) != 1 {
			t.Errorf("Add(%v) => %v want %v", scenario.name, len(createTransaction.RollbackOperations), 1)
		}

		error := createTransaction.Clean()
		if error != nil {
			if scenario.expectError == false {
				t.Errorf("Clean(%v) => %v want %v", scenario.name, error, scenario.expectError)
			}
		} else {
			if scenario.expectError == true {
				t.Errorf("Clean(%v) => %v want %v", scenario.name, error, scenario.expectError)
			}
		}

		createTransaction.Complete()
	}
}

func TestMultipleRollbacksSameTypes(t *testing.T) {
	// setup some test scenarios
	var testCases = []struct {
		name         string
		expectError  bool
		testFunction RollbackMetadata
	}{
		{"action1", false, func(metadata *secrets.Secret) error {
			fmt.Println("first function")
			return nil
		}},
		{"action2", false, func(metadata *secrets.Secret) error {
			fmt.Println("second function")
			return nil
		}},
		{"action3", false, func(metadata *secrets.Secret) error {
			fmt.Println("third function")
			return nil
		}},
	}

	createTransaction := NewTransaction()
	for _, scenario := range testCases {
		testMeta := NewMetadataRollback(scenario.testFunction, secrets.NewSecret())
		createTransaction.Add(testMeta)
	}

	if len(createTransaction.RollbackOperations) != len(testCases) {
		t.Errorf("Add() => %v want %v", len(createTransaction.RollbackOperations), len(testCases))
	}

	if error := createTransaction.Clean(); error != nil {
		t.Errorf("Clean() => %v want %v", error, "nil")
	}

	createTransaction.Complete()
}

func TestMultipleRollbacksDifferentTypes(t *testing.T) {
	// setup some test scenarios

	testFunction1 := func(metadata *secrets.Secret) error {
		fmt.Println("test metadata function")
		return nil
	}

	testFunction2 := func(parm1 int, parm2 string) error {
		fmt.Printf("silly function [%v] [%v]\n", parm1, parm2)
		return nil
	}

	testFunction3 := func(parm1 string, parm2 string, parm3 string, i interface{}) error {
		fmt.Printf("silly keyID function [%v] [%v]\n", parm1, parm2)
		return nil
	}

	createTransaction := NewTransaction()
	testMeta := NewMetadataRollback(testFunction1, secrets.NewSecret())
	createTransaction.Add(testMeta)
	testSilly := newSillyRollback(testFunction2, 100, "woohoo")
	createTransaction.Add(testSilly)
	testKID := NewKeyIDRollback(testFunction3, "1234-567-891110", "woohoo", "blah", nil)
	createTransaction.Add(testKID)

	if len(createTransaction.RollbackOperations) != 3 {
		t.Errorf("Add() => %v want %v", len(createTransaction.RollbackOperations), 3)
	}

	if error := createTransaction.Clean(); error != nil {
		t.Errorf("Clean() => %v want %v", error, "nil")
	}

	createTransaction.Complete()
}

// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package db

import (
	"errors"

	"github.ibm.com/Alchemy-Key-Protect/kp-go-config"
)

type dbConfiguration struct {
	Host   string `json:"Host"`
	User   string `json:"User"`
	Passwd string `json:"Passwd"`
	Name   string `json:"Name"`
	Table  string `json:"Table"`
}

// BarbicanRefs is a structure for holding needed ids for translations of ids
type BarbicanRefs struct {
	SecretID string
	OrderID  string
	KpID     string
}

// ErrNotFound is for when an entry in the db is not found
var ErrNotFound = errors.New("Not found")

//DB The interface for interacting with the csv database
type DB interface {
	Add(space string, org string, refs *BarbicanRefs) error
	Update(space string, org string, refs *BarbicanRefs) error
	Get(space string, org string, kpID string) (*BarbicanRefs, error)
	Delete(space string, org string, kpID string) error
}

//NewDBInstance Creates a new instance of the DB.
func NewDBInstance() DB {
	useCassandra := configuration.Get().GetBool("featuretoggle.cassandra")
	if useCassandra {
		db, err := newCassandraInstance()
		if err != nil {
			panic(err.Error())
		}
		return db
	}
	return newMYSQLinstance()
}

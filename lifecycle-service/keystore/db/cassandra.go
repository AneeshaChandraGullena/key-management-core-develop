// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package db

/*
This DB package is ONLY to be used for ID translations between KP ids and secret or order refs.
*/
import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/gocql/gocql"
	config "github.ibm.com/Alchemy-Key-Protect/kp-go-config"
)

//tables is used to hold the tables used for ID translation
//tables is keyed on the name of table. The value is a list of columns
//in that table.
var tables map[string][]string

//table names related to KP ID translation in cassandra
/* #nosec */
const (
	idBySecret = "id_by_secret_ref"
	idByOrder  = "id_by_order_ref"
	idTracker  = "id_tracker"
)

//column names used in cassandra
/* #nosec */
const (
	kpIDColumn      = "keyprotect_id"
	secretRefColumn = "secret_ref"
	orderRefColumn  = "order_ref"
	spaceIDColumn   = "space_id"
	orgIDColumn     = "org_id"
)

//Keyspace used for ID translations
const idNameSpace = "kp_id_tracker"

func init() {
	tables = make(map[string][]string)
	tables[idBySecret] = []string{kpIDColumn, orgIDColumn, secretRefColumn}
	tables[idByOrder] = []string{kpIDColumn, orgIDColumn, orderRefColumn}
	tables[idTracker] = []string{kpIDColumn, secretRefColumn, orderRefColumn, spaceIDColumn, orgIDColumn}
}

var dbInstance *cassandraDB
var once sync.Once

type cassandraDB struct {
	Configuration *dbConfiguration
	Cluster       *gocql.ClusterConfig
	Session       *gocql.Session
	mu            sync.RWMutex
}

func (d *cassandraDB) refreshSession() error {
	var err error
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Session, err = d.Cluster.CreateSession()
	if err == nil && d.Session.Closed() {
		err = gocql.ErrSessionClosed
	}
	return err
}

//NewDBInstance Creates a new instance of the DB.
func newCassandraInstance() (DB, error) {
	var err error
	once.Do(func() {
		dbInstance = new(cassandraDB)
		dbInstance.Configuration = new(dbConfiguration)
		err = loadConfig(dbInstance.Configuration)
		if err != nil {
			return
		}

		dbInstance.Cluster = gocql.NewCluster(dbInstance.Configuration.Host)
		dbInstance.Cluster.Keyspace = idNameSpace
		dbInstance.Cluster.Consistency = gocql.Quorum
		dbInstance.Cluster.ProtoVersion = 3

		dbInstance.Session, err = dbInstance.Cluster.CreateSession()
	})
	if err != nil || dbInstance.Session == nil || dbInstance.Session.Closed() {
		err = dbInstance.refreshSession()
	}

	return dbInstance, err
}

/*
Add will add a new mapping into cassandra that relates the kp id to the given
secret ref and order ref.
*/
func (d *cassandraDB) Add(space string, org string, refs *BarbicanRefs) error {
	if refs == nil {
		return errors.New(http.StatusText(http.StatusInternalServerError) + ": Request requires translation references")
	}

	if len(space) == 0 {
		return errors.New("Missing space refs")
	}

	if len(refs.KpID) == 0 || len(refs.SecretID) == 0 {
		return errors.New("Missing references")
	}

	insertBatch := d.Session.NewBatch(gocql.LoggedBatch)
	var query string
	for table, columns := range tables {
		var columnNames bytes.Buffer
		columnValues := make([]interface{}, 10)
		for i, column := range columns {
			columnNames.Write([]byte(column))
			columnNames.Write([]byte(","))
			if column == kpIDColumn {
				columnValues[i] = refs.KpID
			} else if column == secretRefColumn {
				columnValues[i] = refs.SecretID
			} else if column == orderRefColumn {
				columnValues[i] = refs.OrderID
			} else if column == spaceIDColumn {
				columnValues[i] = space
			} else if column == orgIDColumn {
				columnValues[i] = org
			}
		}
		columns := strings.TrimSuffix(columnNames.String(), ",")
		/* #nosec */
		query = fmt.Sprintf("INSERT INTO %s (%s) VALUES (?,?,?,?)", table, columns)
		insertBatch.Query(query, columnValues...)
	}
	return d.Session.ExecuteBatch(insertBatch)
}

/*
Updates the given row. Cassandra will overwrite any values when inserted, so this
function simply calls add.
*/
func (d *cassandraDB) Update(space string, org string, refs *BarbicanRefs) error {
	return d.Add(space, org, refs)
}

func (d *cassandraDB) Get(space string, org string, kpID string) (*BarbicanRefs, error) {
	var secret string
	var order string
	tableName := string(idTracker)
	/* #nosec */
	query := fmt.Sprintf("SELECT %s,%s FROM %s WHERE %s = ? AND %s = ? LIMIT 1", secretRefColumn, orderRefColumn, tableName, spaceIDColumn, kpIDColumn)
	err := d.Session.Query(query, space, kpID).Consistency(gocql.Quorum).Scan(&secret, &order)
	if err != nil {
		return nil, err
	}
	return &BarbicanRefs{OrderID: order, SecretID: secret, KpID: kpID}, nil
}

func (d *cassandraDB) Delete(space string, org string, kpID string) error {
	//Right now this is a no-op as we soft delete secrets.
	return nil
}

func loadConfig(configuration *dbConfiguration) error {
	file, err := os.Open(config.Get().GetString("database.credentialsLocation"))
	if err != nil {
		return err
	}

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	return json.Unmarshal(bytes, configuration)
}

// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package db

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"log"

	"github.com/go-sql-driver/mysql"
	config "github.ibm.com/Alchemy-Key-Protect/kp-go-config"
)

/* #nosec */
const (
	kpIDColumnSQL      = "kp_id"
	secretRefColumnSQL = "secret_ref"
	orderRefColumnSQL  = "order_ref"
	spaceIDColumnSQL   = "space_id"
	deletedColumnSQL   = "deleted"
)

//Keyspace used for ID translations
const idTableSQL = "keyprotect_ids"
const deadlockError = 1213
const retries = 4

const (
    tlsConfigName = "kpcustom"
)

type mysqlDB struct {
	dbConnection *sql.DB
}

var dbConnectString = "?charset=utf8"
var mysqlInstance *mysqlDB
var mysqlOnce sync.Once

//NewDBInstance Creates a new instance of the DB.
func newMYSQLinstance() DB {
	mysqlOnce.Do(createMYSQLConnection)
	return mysqlInstance
}

func (d *mysqlDB) Add(space string, org string, refs *BarbicanRefs) error {
	if refs == nil {
		return errors.New(http.StatusText(http.StatusInternalServerError) + ": Request requires translation references")
	}

	//Add into table keyed on space.
	/* #nosec */
	query := fmt.Sprintf("INSERT INTO %s (%s,%s,%s,%s) VALUES (?,?,?,?)", idTableSQL, kpIDColumnSQL, spaceIDColumnSQL, secretRefColumnSQL, orderRefColumnSQL)
	insert, err := d.dbConnection.Prepare(query)
	if err != nil && isDeadLockError(err) {
		for i := 0; i < retries; i++ {
			insert, err = d.dbConnection.Prepare(query)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		return err
	}
	defer insert.Close()
	_, err = insert.Exec(refs.KpID, space, refs.SecretID, refs.OrderID)
	if err != nil {
		return err
	}

	return nil
}

func (d *mysqlDB) Get(space string, org string, kpID string) (*BarbicanRefs, error) {
	/* #nosec */
	query := fmt.Sprintf("SELECT %s,%s FROM %s WHERE %s = ? AND %s = ? AND %s = ?", secretRefColumnSQL, orderRefColumnSQL, idTableSQL, spaceIDColumnSQL, kpIDColumnSQL, deletedColumnSQL)
	get, err := d.dbConnection.Prepare(query)

	if err != nil && isDeadLockError(err) {
		for i := 0; i < retries; i++ {
			get, err = d.dbConnection.Prepare(query)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		return nil, err
	}

	defer get.Close()

	res := get.QueryRow(space, kpID, false)
	ref := &BarbicanRefs{KpID: kpID}
	res.Scan(&ref.SecretID, &ref.OrderID)
	if ref.SecretID == "" && ref.OrderID == "" {
		return nil, ErrNotFound
	}
	return ref, nil
}

func (d *mysqlDB) Update(space string, org string, refs *BarbicanRefs) error {
	if refs == nil {
		return errors.New(http.StatusText(http.StatusInternalServerError) + ": Request requires translation references")
	}

	/* #nosec */
	query := fmt.Sprintf("UPDATE %s SET %s=?,%s=? WHERE %s=? AND %s=?", idTableSQL, secretRefColumnSQL, orderRefColumnSQL, kpIDColumnSQL, spaceIDColumnSQL)
	update, err := d.dbConnection.Prepare(query)
	if err != nil && isDeadLockError(err) {
		for i := 0; i < retries; i++ {
			update, err = d.dbConnection.Prepare(query)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		return err
	}
	defer update.Close()
	status, err := update.Exec(refs.SecretID, refs.OrderID, refs.KpID, space)
	if err != nil {
		return err
	}
	rowsAffected, err := status.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return errors.New("Issue seen with Order processing")
	}
	return nil
}

func (d *mysqlDB) Delete(space string, org string, kpID string) error {
	/* #nosec */
	query := fmt.Sprintf("UPDATE %s SET %s=? WHERE %s = ? AND %s = ?", idTableSQL, deletedColumnSQL, spaceIDColumnSQL, kpIDColumnSQL)
	del, err := d.dbConnection.Prepare(query)
	if err != nil && isDeadLockError(err) {
		for i := 0; i < retries; i++ {
			del, err = d.dbConnection.Prepare(query)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		return err
	}
	defer del.Close()
	del.Exec(true, space, kpID)
	return nil
}

// setup TLS on 2 conditions.
// 1.  We're not in local test environment. This enables `go test` to working
// 2.  The feature toggle is set to true
//
// Notes: check for test environment.  Production shouldn't have any configuration value for `env`
func setupTLS() {
    // don't setup TLS if TLS toggle is disabled
    enableTLS := config.Get().GetBool("feature_toggles.enableTLS")
    if !enableTLS {
	log.Printf("feature is disabled toggle: %v\n", config.Get().GetBool("feature_toggles.enableTLS"))
        return
    }

    // with TLS connection string must look like: ?charset=utf8&tls=kpcustom
    dbConnectString = dbConnectString + "&tls=" + tlsConfigName

    // setup TLS config (see https://godoc.org/github.com/go-sql-driver/mysql#RegisterTLSConfig)
    rootCertPool := x509.NewCertPool()
    caCert, err := ioutil.ReadFile(config.Get().GetString("certs.base_path") + "/" + config.Get().GetString("certs.ca_cert_pem"))
    if err != nil {
        // certificates are required, so fail fast
        panic(fmt.Sprintf("CA pem required:\n%v\n", err))
    }
    if ok := rootCertPool.AppendCertsFromPEM(caCert); !ok {
        // something is wrong, so fail fast
        panic(fmt.Sprintf("Failed to append PEM:\n%v\n", err))
    }

    clientCert := make([]tls.Certificate, 0, 1)
    certs, err := tls.LoadX509KeyPair(config.Get().GetString("certs.base_path")+"/"+config.Get().GetString("certs.client_cert_pem"),
        config.Get().GetString("certs.base_path")+"/"+config.Get().GetString("certs.client_key_pem"))

    if err != nil {
        // client cert key pair is required, so fail fast
        panic(fmt.Sprintf("Client certs required:\n%v\n", err))
    }

    clientCert = append(clientCert, certs)

    // Note: Although we've registered better ciphers, the current version of mysql fails with `handshake failures` except for this cipher: tls.TLS_RSA_WITH_AES_256_GCM_SHA384
    mysql.RegisterTLSConfig(tlsConfigName, &tls.Config{
        RootCAs:      rootCertPool,
        Certificates: clientCert,
        MinVersion:   tls.VersionTLS12,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
        },
        ServerName: config.Get().GetString("certs.server_name"),
        //InsecureSkipVerify: true,
    })
}

func createMYSQLConnection() {
	var credentialsLocation string
	if credentialsLocation = os.Getenv("MARIA_CREDENTIALS_LOCATION"); credentialsLocation == "" {
		credentialsLocation = config.Get().GetString("database.credentialsLocation")
	}

	file, err := os.Open(credentialsLocation)
	if err != nil {
		panic(err.Error())
	}

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		panic(err.Error())
	}

	configuration := &dbConfiguration{}

	err = json.Unmarshal(bytes, &configuration)
	if err != nil {
		panic(err.Error())
	}


	setupTLS()
	loginString := fmt.Sprintf("%s:%s@tcp(%s)/%s%s", configuration.Name, configuration.Passwd, configuration.Host, configuration.Name, dbConnectString)

	//Login
	db, err := sql.Open("mysql", loginString)
	if err != nil {
		panic(err.Error())
	}

	mysqlInstance = new(mysqlDB)
	mysqlInstance.dbConnection = db
}

func isDeadLockError(err error) bool {
	if err == nil {
		return false
	}
	if driverErr, ok := err.(*mysql.MySQLError); ok {
		if driverErr.Number == deadlockError {
			return true
		}
	}
	return false
}

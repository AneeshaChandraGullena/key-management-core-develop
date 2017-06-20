// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package barbican

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-kit/kit/log"
	"github.com/satori/go.uuid"

	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/definitions"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/keystore/barbican/client"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/keystore/db"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/transactions"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-config"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-consts"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/secrets"
)

const (
	//MaxRetries matches the total number of Barbican nodes
	MaxRetries = 4
)

type keystore struct {
	barbicanClient client.Client
	logger         log.Logger
	headers        *communications.Headers
	database       db.DB
}

// translateID is a helper function for GetPayload and Delete
// will translate a key protect id into either a barbican secret id
func translateID(keyprotectID, space, org string, s *keystore) (*db.BarbicanRefs, error) {
	data, err := s.database.Get(space, org, keyprotectID)
	if err != nil {
		return nil, err
	}

	if data == nil || (data.SecretID == "" && data.OrderID == "") {
		return nil, errors.New(http.StatusText(http.StatusNotFound) + ": Key not found")
	}

	return data, nil
}

func extractBluemixSpace(s *keystore) (string, error) {
	headers := s.headers
	if headers == nil {
		return "", errors.New(http.StatusText(http.StatusBadRequest) + ": Headers required")
	}

	bluemixSpace := headers.BluemixSpace
	if bluemixSpace == "" {
		return "", errors.New(http.StatusText(http.StatusBadRequest) + ": Header Bluemix-Space required")
	}
	return bluemixSpace, nil
}

func extractBluemixOrg(s *keystore) (string, error) {
	headers := s.headers
	if headers == nil {
		return "", errors.New(http.StatusText(http.StatusBadRequest) + ": Headers required")
	}

	bluemixOrg := headers.BluemixOrg
	if bluemixOrg == "" {
		return "", errors.New(http.StatusText(http.StatusBadRequest) + ": Header Bluemix-Org required")
	}
	return bluemixOrg, nil
}

func retrievePayload(s *keystore, secretRef string, isOrder bool) (string, error) {
	var payload string
	var err error
	if isOrder {
		payload, err = s.barbicanClient.GetPayload(secretRef, constants.OctetStreamMime)
	} else {
		payload, err = s.barbicanClient.GetPayload(secretRef, constants.TextPlainMime)
	}

	if err != nil {
		return "", err
	}

	return payload, nil
}

//GetPayload : Get a payload with the given keyprotect ID
func (s *keystore) GetPayload(keyprotectID string) (string, secrets.KeyStates, error) {
	space, extractErr := extractBluemixSpace(s)
	if extractErr != nil {
		return "", secrets.Destroyed, extractErr
	}

	org, extractErr := extractBluemixOrg(s)
	if extractErr != nil {
		return "", secrets.Destroyed, extractErr
	}

	var ref *db.BarbicanRefs
	var errTranslate error
	for i := 0; i < MaxRetries; i++ {
		ref, errTranslate = translateID(keyprotectID, space, org, s)
		if errTranslate == nil {
			break
		}
	}

	if errTranslate != nil {
		return "", secrets.Destroyed, errTranslate
	}

	//Need to retrieve the secret ref from the order.
	//If the order is not active yet we simply let the caller know that
	//the secret is still pending.
	if len(ref.OrderID) > 0 && len(ref.SecretID) == 0 {
		var check *client.CheckOrderResponse
		var err error
		for i := 0; i < MaxRetries; i++ {
			check, err = s.barbicanClient.CheckOrder(ref.OrderID)
			if err == nil {
				break
			}
		}

		if err != nil {
			return "", secrets.Destroyed, err
		}

		if check.KeyStatus == secrets.GenerationError {
			return "", secrets.Destroyed, nil
		}
		if check.KeyStatus == secrets.Activation {
			ref.SecretID = check.SecretRef
			for i := 0; i < MaxRetries; i++ {
				err = s.database.Update(s.headers.BluemixSpace, s.headers.BluemixOrg, ref)
				if err == nil {
					break
				}
			}
			if err != nil {
				s.barbicanClient.DeleteOrder(ref.OrderID)
			}
		} else {
			return "", check.KeyStatus, nil
		}
	}

	var payload string
	var err error
	for i := 0; i < MaxRetries; i++ {
		payload, err = retrievePayload(s, ref.SecretID, len(ref.OrderID) != 0)
		if err == nil {
			break
		}
	}
	return payload, secrets.Activation, err
}

func createID(refs *db.BarbicanRefs, space string, org string, s *keystore) (string, error) {
	if refs == nil {
		return "", errors.New(http.StatusText(http.StatusInternalServerError) + ": Request requires translation references")
	}

	var keyprotectID string
	var errGet error

	// Go Until you a "Not Found" Error is thrown. This would imply an open ID.
	// If some other error is thrown, return that error
	for errGet == nil {
		keyprotectID = uuid.NewV4().String()
		_, errGet = s.database.Get(space, org, keyprotectID)
		if errGet != nil && errGet != db.ErrNotFound {
			return "", errGet
		}
	}

	refs.KpID = keyprotectID
	errAdd := s.database.Add(space, org, refs)
	if errAdd != nil {
		return "", errAdd
	}

	return keyprotectID, nil
}

func storeSecret(s *keystore, secret *secrets.Secret, createTx *transactions.Transaction) (string, error) {
	secretID, err := s.barbicanClient.PostSecret(&client.PostSecretRequest{
		Name:               secret.Name,
		Payload:            secret.Payload,
		PayloadContentType: constants.TextPlainMime,
	})
	if err != nil {
		s.logger.Log("err", err, "correlation_id", s.headers.CorrelationID)
		return "", err
	}

	rbDeleteSecret := transactions.NewHsmCreateSecretRollback(s.barbicanClient.DeleteSecret, secretID)
	createTx.Add(rbDeleteSecret)
	space, extractErr := extractBluemixSpace(s)
	if extractErr != nil {
		return "", extractErr
	}

	org, extractErr := extractBluemixOrg(s)
	if extractErr != nil {
		return "", extractErr
	}

	id, err := createID(&db.BarbicanRefs{SecretID: secretID}, space, org, s)
	if err != nil {
		return "", err
	}

	rbDeleteID := transactions.NewKeyIDRollback(deleteID, id, space, org, s)
	createTx.Add(rbDeleteID)

	secret.SetState(secrets.Activation)
	return id, nil
}

func generateSecret(s *keystore, secret *secrets.Secret) (string, error) {
	// TODO: this is temporary code until we have code put in place for to check for defaults, bad values, etc in the transport layer. TSC. Dec 14th, 2016

	// AES default. Need so that we can put this into metadata table.
	secret.AlgorithmType = "AES"

	// just in case this doesn't exist
	if secret.AlgorithmMetadata == nil {
		secret.AlgorithmMetadata = make(map[string]string)
	}

	// Mode GCM default. Need so that we can put this into metadata table.
	secret.AlgorithmMetadata["mode"] = "GCM"
	// bitLength 256 default. Need so that we can put this into metadata table.
	secret.AlgorithmMetadata["bitLength"] = "256"

	algorithmType := secret.AlgorithmType
	mode := secret.AlgorithmMetadata["mode"]

	// TODO: should be no error as this is defaulted for now. will need to be changed in the future where there is possiblity of errors. TSC. Dec 14th, 2016
	bitLength, _ := strconv.Atoi(secret.AlgorithmMetadata["bitLength"])

	orderID, err := s.barbicanClient.PostOrder(&client.PostOrderRequest{
		Type: "key",
		Meta: &client.OrderMeta{
			Name:               secret.Name,
			Algorithm:          algorithmType,    //Should be found AlgorithmType
			BitLength:          int32(bitLength), //Should be found in algorithm metadata (not yet there)
			Mode:               mode,             // Should be in algorithm metadata (not yet there)
			PayloadContentType: constants.OctetStreamMime,
		},
	})
	if err != nil {
		s.logger.Log("err", err, "correlation_id", s.headers.CorrelationID)
		return "", err
	}

	space, extractErr := extractBluemixSpace(s)
	if extractErr != nil {
		return "", extractErr
	}

	org, extractErr := extractBluemixOrg(s)
	if extractErr != nil {
		return "", extractErr
	}

	secret.SetState(secrets.Preactivation)
	return createID(&db.BarbicanRefs{OrderID: orderID}, space, org, s)
}

// CreateSecret creates a secret using inside the barbican user defined metadata table
func (s *keystore) CreateSecret(secret *secrets.Secret, createTx *transactions.Transaction) (string, error) {
	if len(secret.Payload) > 0 {
		return storeSecret(s, secret, createTx)
	}
	return generateSecret(s, secret)
}

//deleteID takes an interface so that we can perform rollbacks using this function. The interface
//protects other packages from being exposed to the keystore concept.
func deleteID(keyprotectID string, space string, org string, i interface{}) error {
	if s, ok := i.(*keystore); ok {
		return s.database.Delete(space, org, keyprotectID)
	}
	return fmt.Errorf("Requires type *keystore, received %T", i)
}

// DeleteSecret Given a keyprotect ID. Delete the user's secret.
func (s *keystore) DeleteSecret(keyprotectID string, deleteTx *transactions.Transaction) error {
	space, extractErr := extractBluemixSpace(s)
	if extractErr != nil {
		return extractErr
	}

	org, extractErr := extractBluemixOrg(s)
	if extractErr != nil {
		return extractErr
	}

	refs, errTranslate := translateID(keyprotectID, space, org, s)
	if errTranslate != nil {
		return errTranslate
	}

	if len(refs.SecretID) == 0 {
		check, err := s.barbicanClient.CheckOrder(refs.OrderID)
		if err != nil {
			return err
		}

		if check.KeyStatus == secrets.Activation {
			refs.SecretID = check.SecretRef
		} else {
			return errors.New(http.StatusText(http.StatusConflict) + ": Secret generation still in progress. Please try again later.")
		}
	}

	var errBarbicanDelete error

	//TODO: csolis 11/10/2016 - Add CreateID function call to be used for rollbacks
	errBarbicanDelete = s.barbicanClient.DeleteSecret(refs.SecretID)
	if errBarbicanDelete != nil {
		s.logger.Log("err", errBarbicanDelete.Error(), "correlation_id", s.headers.CorrelationID)
		return errBarbicanDelete
	}

	deleteIDErr := deleteID(keyprotectID, space, org, s)
	if deleteIDErr != nil {
		s.logger.Log("err", deleteIDErr, "correlation_id", s.headers.CorrelationID)
		return deleteIDErr
	}

	if refs.OrderID != "" {
		//This function doesn't return an error. It doesn't really matter as this
		//will eventually be cleaned out by a background script.
		retries := 0
		for retries < MaxRetries {
			if err := s.barbicanClient.DeleteOrder(refs.OrderID); err == nil {
				break
			}
			retries++
		}
		if retries == MaxRetries {
			s.logger.Log("correlation_id", s.headers.CorrelationID, "order_ref", refs.OrderID, "err", "CRITICAL - Cannot delete order ID")
		}
	}

	return nil
}

// CheckSecret: Given a keyprotect id, is the secret active?
func (s *keystore) CheckSecret(keyprotectID string) (secrets.KeyStates, error) {
	space, extractErr := extractBluemixSpace(s)
	if extractErr != nil {
		return secrets.Destroyed, extractErr
	}

	org, extractErr := extractBluemixOrg(s)
	if extractErr != nil {
		return secrets.Destroyed, extractErr
	}

	refs, errTranslate := translateID(keyprotectID, space, org, s)
	if errTranslate != nil {
		return secrets.Destroyed, errTranslate
	}

	if len(refs.SecretID) != 0 {
		return secrets.Activation, nil
	}

	check, err := s.barbicanClient.CheckOrder(refs.OrderID)
	if err != nil {
		return secrets.Destroyed, err
	}

	if check.KeyStatus == secrets.GenerationError {
		return secrets.Destroyed, nil
	}

	if check.KeyStatus == secrets.Activation && len(check.SecretRef) > 0 {
		refs.KpID = keyprotectID
		refs.SecretID = check.SecretRef
		if err = s.database.Update(s.headers.BluemixSpace, s.headers.BluemixOrg, refs); err == nil {
			// if successful on update, delete order from barbican table
			s.barbicanClient.DeleteOrder(refs.OrderID)
		}
		return secrets.Activation, nil
	}

	return secrets.Preactivation, nil
}

// NewBarbicanKeystore will return a new barbican Keystore
func NewBarbicanKeystore(auth *communications.Headers, logger log.Logger) definitions.Keystore {
	config := configuration.Get()
	cli := client.NewClient(config.GetString("openstack.barbican.url"), auth)
	s := new(keystore)
	s.barbicanClient = cli
	s.headers = auth
	s.logger = logger
	s.database = db.NewDBInstance()
	return s
}

// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package barbican

import (
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/go-kit/kit/log"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/keystore/barbican/client"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/keystore/db"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/secrets"
)

var (
	testKeystore       *keystore
	fDatabase          *fDB
	fBarbicanClient    *fBC
	nilOverwriteForAdd bool
)

func init() {
	fDatabase = new(fDB)
	fBarbicanClient = new(fBC)
	testKeystore = &keystore{
		barbicanClient: fBarbicanClient,
		logger:         log.NewNopLogger(),
		database:       fDatabase,
	}
}

type fDB struct {
	err        error
	returnRefs *db.BarbicanRefs
}

func (fdb *fDB) Add(space string, org string, refs *db.BarbicanRefs) error {
	err := fdb.err
	if nilOverwriteForAdd == true {
		err = nil
	}
	return err
}

func (fdb *fDB) Update(space string, org string, refs *db.BarbicanRefs) error {
	return fdb.err
}

func (fdb *fDB) Get(space string, org string, kpID string) (*db.BarbicanRefs, error) {
	return fdb.returnRefs, fdb.err
}

func (fdb *fDB) Delete(space string, org string, kpID string) error {
	return fdb.err
}

func (fdb *fDB) InjectError(err error) {
	fdb.err = err
}

func (fdb *fDB) RemoveError() {
	fdb.err = nil
}

func (fdb *fDB) InjectRefs(refs *db.BarbicanRefs) {
	fdb.returnRefs = refs
}

func (fdb *fDB) RemoveRefs() {
	fdb.returnRefs = nil
}

type fBC struct {
	err                error
	stringResponse     string
	checkOrderResponse *client.CheckOrderResponse
}

func (fb *fBC) PostSecret(secret *client.PostSecretRequest) (string, error) {
	return fb.stringResponse, fb.err
}

func (fb *fBC) PostOrder(order *client.PostOrderRequest) (string, error) {
	return fb.stringResponse, fb.err
}

func (fb *fBC) CheckOrder(orderRef string) (*client.CheckOrderResponse, error) {
	return fb.checkOrderResponse, fb.err
}

func (fb *fBC) GetPayload(secretID string, accept string) (string, error) {
	return fb.stringResponse, fb.err
}

func (fb *fBC) DeleteOrder(orderRef string) error {
	return fb.err
}

func (fb *fBC) DeleteSecret(ID string) error {
	return fb.err
}

func (fb *fBC) InjectError(err error) {
	fb.err = err
}

func (fb *fBC) RemoveError() {
	fb.err = nil
}

func headerSetup() {
	testKeystore.headers = new(communications.Headers)

	testSpace := "test-space"
	testKeystore.headers.BluemixSpace = testSpace

	testOrg := "test-org"
	testKeystore.headers.BluemixOrg = testOrg
}

func cleanUp() {
	// clean up headers
	testKeystore.headers = nil

	// clean up nilOverwriteForAdd
	nilOverwriteForAdd = false

	// clean up injected errors
	fDatabase.RemoveError()
	fBarbicanClient.RemoveError()

	// clean up injected refs
	fDatabase.RemoveRefs()

}

func TestTranslateIDErrorDB(t *testing.T) {
	// test db error
	testDBErr := errors.New("test-db-error")
	fDatabase.InjectError(testDBErr)

	_, errDBErr := translateID("", "", "", testKeystore)
	if errDBErr != testDBErr {
		t.Errorf("Expected %s, received %+v", testDBErr.Error(), errDBErr)
	}

	cleanUp()
}

func TestTranslateIDErrorDBErrorKeyNotFound(t *testing.T) {
	// test "Key Not Found" error
	errMsg := http.StatusText(http.StatusNotFound) + ": Key not found"

	_, errKeyNotFound := translateID("", "", "", testKeystore)
	if errKeyNotFound == nil || errKeyNotFound.Error() != errMsg {
		t.Errorf("Expected %s, received %+v", errMsg, errKeyNotFound)
	}

	cleanUp()
}

func TestTranslateIDGoodPath(t *testing.T) {
	testRefs := &db.BarbicanRefs{
		SecretID: "test-secret-id",
		OrderID:  "test-order-id",
	}
	fDatabase.InjectRefs(testRefs)

	refs, errGoodPath := translateID("", "", "", testKeystore)
	if errGoodPath != nil {
		t.Error("Unexpected Error")
	}

	if !reflect.DeepEqual(testRefs, refs) {
		t.Errorf("Expected %+v, received %+v", testRefs, refs)
	}

	cleanUp()
}

func TestExtractBluemixSpaceErrorHeadersRequired(t *testing.T) {
	errMsgHeadersRequired := http.StatusText(http.StatusBadRequest) + ": Headers required"

	_, errHeadersRequired := extractBluemixSpace(testKeystore)
	if errHeadersRequired == nil || errHeadersRequired.Error() != errMsgHeadersRequired {
		t.Errorf("Expected %s, received %+v", errHeadersRequired, errMsgHeadersRequired)
	}

	cleanUp()
}

func TestExtractBluemixSpaceErrorBluemixSpaceRequired(t *testing.T) {
	errMsgBluemixSpaceRequired := http.StatusText(http.StatusBadRequest) + ": Header Bluemix-Space required"

	testKeystore.headers = new(communications.Headers)

	_, errBluemixSpaceRequired := extractBluemixSpace(testKeystore)
	if errBluemixSpaceRequired == nil || errBluemixSpaceRequired.Error() != errMsgBluemixSpaceRequired {
		t.Errorf("Expected %s, received %+v", errMsgBluemixSpaceRequired, errBluemixSpaceRequired)
	}

	cleanUp()
}

func TestExtractBluemixSpaceGoodPath(t *testing.T) {
	testKeystore.headers = new(communications.Headers)

	testSpace := "test-space"
	testKeystore.headers.BluemixSpace = testSpace

	space, errGoodPath := extractBluemixSpace(testKeystore)
	if errGoodPath != nil {
		t.Error("Unexpected Error")
	}

	if space != testSpace {
		t.Errorf("Expected %s, received %s", testSpace, space)
	}

	cleanUp()
}

func TestExtractBluemixOrgErrorHeadersRequired(t *testing.T) {
	errMsgHeadersRequired := http.StatusText(http.StatusBadRequest) + ": Headers required"

	_, errHeadersRequired := extractBluemixOrg(testKeystore)
	if errHeadersRequired == nil || errHeadersRequired.Error() != errMsgHeadersRequired {
		t.Errorf("Expected %s, received %+v", errHeadersRequired, errMsgHeadersRequired)
	}

	cleanUp()
}

func TestExtractBluemixOrgErrorBluemixSpaceRequired(t *testing.T) {
	errMsgBluemixOrgRequired := http.StatusText(http.StatusBadRequest) + ": Header Bluemix-Org required"

	testKeystore.headers = new(communications.Headers)

	_, errBluemixOrgRequired := extractBluemixOrg(testKeystore)
	if errBluemixOrgRequired == nil || errBluemixOrgRequired.Error() != errMsgBluemixOrgRequired {
		t.Errorf("Expected %s, received %+v", errMsgBluemixOrgRequired, errBluemixOrgRequired)
	}

	cleanUp()
}

func TestExtractBluemixOrgGoodPath(t *testing.T) {
	testKeystore.headers = new(communications.Headers)

	testOrg := "test-org"
	testKeystore.headers.BluemixOrg = testOrg

	org, errGoodPath := extractBluemixOrg(testKeystore)
	if errGoodPath != nil {
		t.Error("Unexpected Error")
	}

	if org != testOrg {
		t.Errorf("Expected %s, received %s", testOrg, org)
	}

	cleanUp()
}

func TestRetrievePayloadOrder(t *testing.T) {
	testError := errors.New("test-payloadResponse-error")
	fBarbicanClient.InjectError(testError)

	_, errPayloadResponseIsOrder := retrievePayload(testKeystore, "", true)
	if errPayloadResponseIsOrder != testError {
		t.Errorf("Expected %s, received %+v", testError.Error(), errPayloadResponseIsOrder)
	}

	cleanUp()
}

func TestRetrievePayloadSecret(t *testing.T) {
	testError := errors.New("test-payloadResponse-error")
	fBarbicanClient.InjectError(testError)

	_, errPayloadResponseNotOrder := retrievePayload(testKeystore, "", false)
	if errPayloadResponseNotOrder != testError {
		t.Errorf("Expected %s, received %+v", testError.Error(), errPayloadResponseNotOrder)
	}

	cleanUp()
}

func TestGetPayloadErrorBluemixSpaceRequired(t *testing.T) {
	testKeystore.headers = new(communications.Headers)

	// test no Bluemix-Space header
	errMsgBluemixSpaceRequired := http.StatusText(http.StatusBadRequest) + ": Header Bluemix-Space required"

	_, _, errBluemixSpaceRequired := testKeystore.GetPayload("")
	if errBluemixSpaceRequired == nil || errBluemixSpaceRequired.Error() != errMsgBluemixSpaceRequired {
		t.Errorf("Expected %s, received %+v", errMsgBluemixSpaceRequired, errBluemixSpaceRequired)
	}

	cleanUp()
}

func TestGetPayloadErrorBluemixOrgRequired(t *testing.T) {
	testKeystore.headers = new(communications.Headers)

	testSpace := "test-space"
	testKeystore.headers.BluemixSpace = testSpace

	// test no Bluemix-Org header
	errMsgBluemixOrgRequired := http.StatusText(http.StatusBadRequest) + ": Header Bluemix-Org required"

	_, _, errBluemixOrgRequired := testKeystore.GetPayload("")
	if errBluemixOrgRequired == nil || errBluemixOrgRequired.Error() != errMsgBluemixOrgRequired {
		t.Errorf("Expected %s, received %+v", errMsgBluemixOrgRequired, errBluemixOrgRequired)
	}

	cleanUp()
}

func TestGetPayloadErrorKeyNotFound(t *testing.T) {
	headerSetup()

	errMsgKeyNotFound := http.StatusText(http.StatusNotFound) + ": Key not found"

	_, _, errKeyNotFound := testKeystore.GetPayload("")
	if errKeyNotFound == nil || errKeyNotFound.Error() != errMsgKeyNotFound {
		t.Errorf("Expected %s, received %+v", errMsgKeyNotFound, errKeyNotFound)
	}

	cleanUp()
}

func TestGetPayloadOrderErrorCheckOrder(t *testing.T) {
	headerSetup()

	testErrorCheckOrder := errors.New("test-CheckOrder-error")
	fBarbicanClient.InjectError(testErrorCheckOrder)

	// barbican client CheckOrder
	testOrderRef := &db.BarbicanRefs{
		OrderID: "test-order-id",
	}
	fDatabase.InjectRefs(testOrderRef)

	_, _, errCheckOrder := testKeystore.GetPayload("")
	if errCheckOrder != testErrorCheckOrder {
		t.Errorf("Expected %s, received %+v", testErrorCheckOrder.Error(), errCheckOrder)
	}

	cleanUp()
}

func TestGetPayloadSecretErrorRetrievePayload(t *testing.T) {
	headerSetup()

	testErrorRetrievePayload := errors.New("test-retrievePayload-error")
	fBarbicanClient.InjectError(testErrorRetrievePayload)

	testSecretRef := &db.BarbicanRefs{
		SecretID: "test-secret-id",
	}
	fDatabase.InjectRefs(testSecretRef)

	// retrievePayload
	_, _, errRetrievePayload := testKeystore.GetPayload("")
	if errRetrievePayload != testErrorRetrievePayload {
		t.Errorf("Expected %s, received %+v", testErrorRetrievePayload.Error(), errRetrievePayload)
	}

	cleanUp()
}

func TestCeateIDErrorNoRefs(t *testing.T) {
	errMsgNoRefs := http.StatusText(http.StatusInternalServerError) + ": Request requires translation references"

	_, errNoRefs := createID(nil, "", "", testKeystore)
	if errNoRefs == nil || errNoRefs.Error() != errMsgNoRefs {
		t.Errorf("Expected %s, received %+v", errMsgNoRefs, errNoRefs)
	}

	cleanUp()
}

func TestCeateIDErrorGet(t *testing.T) {
	testError := errors.New("test-get-error")
	fDatabase.InjectError(testError)

	_, errGet := createID(&db.BarbicanRefs{}, "", "", testKeystore)
	if errGet != testError {
		t.Errorf("Expected %s, received %+v", testError.Error(), errGet)
	}

	cleanUp()
}

func TestCeateIDErrorAdd(t *testing.T) {
	// used to break out of loop
	fDatabase.InjectError(db.ErrNotFound)

	_, errAdd := createID(&db.BarbicanRefs{}, "", "", testKeystore)
	if errAdd != db.ErrNotFound {
		t.Errorf("Expected %s, received %+v", db.ErrNotFound.Error(), errAdd)
	}

	cleanUp()
}

func TestCeateIDGoodPath(t *testing.T) {
	// used to break out of loop
	fDatabase.InjectError(db.ErrNotFound)

	nilOverwriteForAdd = true

	_, errGoodPath := createID(&db.BarbicanRefs{}, "", "", testKeystore)
	if errGoodPath != nil {
		t.Error("Unexpected Error")
	}

	cleanUp()
}

func TestGenerateSecretErrorPost(t *testing.T) {
	testSecret := secrets.NewSecret()

	testKeystore.headers = new(communications.Headers)

	// test post error
	postErr := errors.New("test-post-error")
	fBarbicanClient.InjectError(postErr)

	_, errPostErr := generateSecret(testKeystore, testSecret)
	if errPostErr != postErr {
		t.Errorf("Expected %s, received %+v", postErr.Error(), errPostErr)
	}

	cleanUp()
}

func TestGenerateSecretErrorBluemixSpaceRequired(t *testing.T) {
	testSecret := secrets.NewSecret()

	testKeystore.headers = new(communications.Headers)

	// test no Bluemix-Space header
	errMsgBluemixSpaceRequired := http.StatusText(http.StatusBadRequest) + ": Header Bluemix-Space required"

	_, errBluemixSpaceRequired := generateSecret(testKeystore, testSecret)
	if errBluemixSpaceRequired == nil || errBluemixSpaceRequired.Error() != errMsgBluemixSpaceRequired {
		t.Errorf("Expected %s, received %+v", errMsgBluemixSpaceRequired, errBluemixSpaceRequired)
	}

	cleanUp()
}

func TestGenerateSecretErrorBluemixOrgRequired(t *testing.T) {
	testSecret := secrets.NewSecret()

	testKeystore.headers = new(communications.Headers)

	testSpace := "test-space"
	testKeystore.headers.BluemixSpace = testSpace

	// test no Bluemix-Org header
	errMsgBluemixOrgRequired := http.StatusText(http.StatusBadRequest) + ": Header Bluemix-Org required"

	_, errBluemixOrgRequired := generateSecret(testKeystore, testSecret)
	if errBluemixOrgRequired == nil || errBluemixOrgRequired.Error() != errMsgBluemixOrgRequired {
		t.Errorf("Expected %s, received %+v", errMsgBluemixOrgRequired, errBluemixOrgRequired)
	}

	cleanUp()
}

func TestGenerateSecret(t *testing.T) {
	testSecret := secrets.NewSecret()

	headerSetup()

	// used to break out of loop
	fDatabase.InjectError(db.ErrNotFound)

	nilOverwriteForAdd = true

	_, errGoodPath := generateSecret(testKeystore, testSecret)
	if errGoodPath != nil {
		t.Error("Unexpected Error")
	}

	cleanUp()
}

func TestDeleteIDErrorBadType(t *testing.T) {
	// test incorrect interface type
	errMsg := "Requires type *keystore, received string"
	if err := deleteID("", "", "", "string-type"); err == nil || err.Error() != errMsg {
		t.Errorf("Expected %s, received %+v", errMsg, err)
	}
}

func TestDeleteIDGoodPath(t *testing.T) {
	if err := deleteID("", "", "", testKeystore); err != nil {
		t.Error("Unexpected Error")
	}
}

// TODO: until the code is updated to add the roll back for failed transactions for DeleteSecret, will pass in nil for deleteTx. TSC 4/10/2017

func TestDeleteSecretErrorBluemixSpaceRequired(t *testing.T) {
	testKeystore.headers = new(communications.Headers)

	// test no Bluemix-Space header
	errMsgBluemixSpaceRequired := http.StatusText(http.StatusBadRequest) + ": Header Bluemix-Space required"

	errBluemixSpaceRequired := testKeystore.DeleteSecret("", nil)
	if errBluemixSpaceRequired == nil || errBluemixSpaceRequired.Error() != errMsgBluemixSpaceRequired {
		t.Errorf("Expected %s, received %+v", errMsgBluemixSpaceRequired, errBluemixSpaceRequired)
	}

	cleanUp()
}

func TestDeleteSecretErrorBluemixOrgRequired(t *testing.T) {
	testKeystore.headers = new(communications.Headers)

	testSpace := "test-space"
	testKeystore.headers.BluemixSpace = testSpace

	// test no Bluemix-Org header
	errMsgBluemixOrgRequired := http.StatusText(http.StatusBadRequest) + ": Header Bluemix-Org required"

	errBluemixOrgRequired := testKeystore.DeleteSecret("", nil)
	if errBluemixOrgRequired == nil || errBluemixOrgRequired.Error() != errMsgBluemixOrgRequired {
		t.Errorf("Expected %s, received %+v", errMsgBluemixOrgRequired, errBluemixOrgRequired)
	}

	cleanUp()
}

func TestDeleteSecretErrorKeyNotFound(t *testing.T) {
	headerSetup()

	errMsgKeyNotFound := http.StatusText(http.StatusNotFound) + ": Key not found"

	errKeyNotFound := testKeystore.DeleteSecret("", nil)
	if errKeyNotFound == nil || errKeyNotFound.Error() != errMsgKeyNotFound {
		t.Errorf("Expected %s, received %+v", errMsgKeyNotFound, errKeyNotFound)
	}

	cleanUp()
}

func TestDeleteSecretErrorOrderCheckOrder(t *testing.T) {
	headerSetup()

	testErrorCheckOrder := errors.New("test-CheckOrder-error")
	fBarbicanClient.InjectError(testErrorCheckOrder)

	// barbican client CheckOrder
	testOrderRefs := &db.BarbicanRefs{
		OrderID: "test-order-id",
	}
	fDatabase.InjectRefs(testOrderRefs)

	errCheckOrder := testKeystore.DeleteSecret("", nil)
	if errCheckOrder == nil || errCheckOrder.Error() != testErrorCheckOrder.Error() {
		t.Errorf("Expected %s, received %+v", testErrorCheckOrder.Error(), errCheckOrder)
	}

	cleanUp()
}

func TestDeleteSecretErrorDelete(t *testing.T) {
	headerSetup()

	testErrorDelete := errors.New("test-delete-error")
	fBarbicanClient.InjectError(testErrorDelete)

	testSecretRefs := &db.BarbicanRefs{
		SecretID: "test-secret-id",
	}
	fDatabase.InjectRefs(testSecretRefs)

	errDelete := testKeystore.DeleteSecret("", nil)
	if errDelete != testErrorDelete {
		t.Errorf("Expected %s, received %+v", testErrorDelete.Error(), errDelete)
	}

	cleanUp()
}

func TestCheckSecretErrorBluemixSpaceRequired(t *testing.T) {
	testKeystore.headers = new(communications.Headers)

	// test no Bluemix-Space header
	errMsgBluemixSpaceRequired := http.StatusText(http.StatusBadRequest) + ": Header Bluemix-Space required"

	_, errBluemixSpaceRequired := testKeystore.CheckSecret("")
	if errBluemixSpaceRequired == nil || errBluemixSpaceRequired.Error() != errMsgBluemixSpaceRequired {
		t.Errorf("Expected %s, received %+v", errMsgBluemixSpaceRequired, errBluemixSpaceRequired)
	}

	cleanUp()
}

func TestCheckSecretErrorBluemixOrgRequired(t *testing.T) {
	testKeystore.headers = new(communications.Headers)

	testSpace := "test-space"
	testKeystore.headers.BluemixSpace = testSpace

	// test no Bluemix-Org header
	errMsgBluemixOrgRequired := http.StatusText(http.StatusBadRequest) + ": Header Bluemix-Org required"

	_, errBluemixOrgRequired := testKeystore.CheckSecret("")
	if errBluemixOrgRequired == nil || errBluemixOrgRequired.Error() != errMsgBluemixOrgRequired {
		t.Errorf("Expected %s, received %+v", errMsgBluemixOrgRequired, errBluemixOrgRequired)
	}

	cleanUp()
}

func TestCheckSecretErrorKeyNotFound(t *testing.T) {
	headerSetup()

	errMsgKeyNotFound := http.StatusText(http.StatusNotFound) + ": Key not found"

	_, errKeyNotFound := testKeystore.CheckSecret("")
	if errKeyNotFound == nil || errKeyNotFound.Error() != errMsgKeyNotFound {
		t.Errorf("Expected %s, received %+v", errMsgKeyNotFound, errKeyNotFound)
	}

	cleanUp()
}

func TestDeleteSecretErrorCheckOrder(t *testing.T) {
	headerSetup()

	testErrorCheckOrder := errors.New("test-CheckOrder-error")
	fBarbicanClient.InjectError(testErrorCheckOrder)

	// barbican client CheckOrder
	testOrderRefs := &db.BarbicanRefs{
		OrderID: "test-order-id",
	}
	fDatabase.InjectRefs(testOrderRefs)

	_, errCheckOrder := testKeystore.CheckSecret("")
	if errCheckOrder == nil || errCheckOrder.Error() != testErrorCheckOrder.Error() {
		t.Errorf("Expected %s, received %+v", testErrorCheckOrder.Error(), errCheckOrder)
	}

	cleanUp()
}

func TestCheckSecretGoodPathSecret(t *testing.T) {
	headerSetup()

	testSecretRefs := &db.BarbicanRefs{
		SecretID: "test-secret-id",
	}
	fDatabase.InjectRefs(testSecretRefs)

	// Good
	_, errCheck := testKeystore.CheckSecret("")
	if errCheck != nil {
		t.Error("Unexpected Error")
	}

	cleanUp()
}

func TestNewBarbicanKeystore(t *testing.T) {
	// internal tests used as a safety gaurd for panics
	keystore := NewBarbicanKeystore(nil, nil)
	if keystore == nil {
		t.Fail()
	}
}

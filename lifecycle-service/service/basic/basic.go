// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package basic

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/go-kit/kit/log"

	"context"

	"github.ibm.com/Alchemy-Key-Protect/go-db-service/services/metadata/client"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/definitions"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/keystore"
	corecomms "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/communications"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/transactions"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-config"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/secrets"
)

const (
	//MaxRetries matches the total number of Barbican nodes
	MaxRetries = 4

	// MaxCharLenForEncryptedField should be used for any encrypted field that needs to fit within 255 column schema definition.
	// see the encryption key in the db repo for more details
	MaxCharLenForEncryptedField = 230

	// MinCharLenForSearchableField provides the min number of characters needed for any field that is searchable
	MinCharLenForSearchableField = 2

	// MaxTagsAllowed specifies how many elements of the metadata Tags are allowed
	MaxTagsAllowed = 30

	// MaxCharLenForTags specifies how many characters each tag can contain
	MaxCharLenForTags = 30

	// MaxPayloadLength specifies the how many characters a secret payload may contain
	MaxPayloadLength = 10000

	// MaxMetadataAllowed specifies how many key, value pairs are allowed in Metadata field
	MaxMetadataAllowed = 30

	// MaxCharLenForMetadata specifies how many chars are allowd in key, value pairs in Metadata field
	MaxCharLenForMetadata = 130

	// ContainsReservedCharacterMessage defines a human-readable message for disallowed characters
	ContainsReservedCharacterMessage = "contains a reserved character (angled bracket, colon, ampersand, or vertical pipe)"
)

var ReservedCharacterList = []rune{'<', '>', ':', '&', '|'}

var (
	config       configuration.Configuration
	dbServerPath string
	timeout      int
)

func init() {
	config = configuration.Get()
	dbServerPath = config.GetString("dbService.ipv4_address") + ":" + config.GetString("dbService.port")
	timeout = config.GetInt("timeouts.grpcTimeout")
}

// Service will return a service based on the Service definition
func Service(logger log.Logger, backEndKeystore keystore.Type) definitions.Service {
	return &basicService{
		logger:          logger,
		backEndKeystore: backEndKeystore,
	}
}

type basicService struct {
	logger          log.Logger
	backEndKeystore keystore.Type
}

func (svc basicService) cleanupFailure(tx *transactions.Transaction, id string) {
	svc.logger.Log("info", "Rolling back transaction due to error!", "correlation_id", id)
	if cleanupErr := tx.Clean(); cleanupErr != nil {
		svc.logger.Log("msg", "Failure encountered during rollback. Rollback halted.",
			"correlation_id", id, "err", cleanupErr)
	}
}

func isValidDate(dateString string) error {
	_, err := time.Parse(time.RFC3339, dateString)
	return err
}

func containsReservedCharacter(checkString string) bool {
	for _, runeValue := range checkString {
		for _, charValue := range ReservedCharacterList {
			if runeValue == charValue {
				return true
			}
		}
	}
	return false
}

// validateSecret ensures metadata provided for secret creation meets criteria as follows:
// - There must be a secret
// - Payload must be <= 10000 characters
// - Expiration date must be RFC3339
// - Description must be <= 230 characters
// - Name must be <= 230 characters
// - Tags must be <= 30 characters and not have more than 30 tags
// - Tags cannot contain these characters <, >, &, :, |
// - AlgorithmMetadata must not have more than 30 key, value pairs
// - AlgorithmMetadata key, value pairs <= 130 characters
// - UserMetadata must not have more than 30 key, value pairs
// - UserMetadata key, value pairs <= 130 characters
// - UserMetadata cannot contain these characters <, >, &, :, |
func validateSecret(secret *secrets.Secret) error {
	if secret == nil {
		badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Requires Secret")
		return badRequest
	}

	if len(secret.Payload) > MaxPayloadLength {
		badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Payload too long")
		return badRequest
	}

	if secret.ExpirationDate != "" {
		if err := isValidDate(secret.ExpirationDate); err != nil {
			badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Requires Valid RFC3339 expiration date")
			return badRequest
		}
	}

	if len(secret.Description) > MaxCharLenForEncryptedField {
		badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Description too long")
		return badRequest
	}

	if len(secret.Name) > MaxCharLenForEncryptedField || len(secret.Name) < MinCharLenForSearchableField {
		badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Name incorrect length")
		return badRequest
	}

	if len(secret.Tags) > MaxTagsAllowed {
		badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Too many tags")
		return badRequest
	}

	for _, currentTag := range secret.Tags {
		if len(currentTag) > MaxCharLenForTags {
			badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Tag too long")
			return badRequest
		}
		if containsReservedCharacter(currentTag) {
			badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Tag " + ContainsReservedCharacterMessage)
			return badRequest
		}
	}

	// validate algorithmMetadata
	if len(secret.AlgorithmMetadata) > MaxMetadataAllowed {
		badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Too many algorithm key value pairs")
		return badRequest
	}

	for name, value := range secret.AlgorithmMetadata {
		if len(name) > MaxCharLenForMetadata {
			badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Algorithm metadata key too long")
			return badRequest
		}
		if len(value) > MaxCharLenForMetadata {
			badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Algorithm metadata value too long")
			return badRequest
		}
	}

	// validate UserMetadata
	if len(secret.UserMetadata) > MaxMetadataAllowed {
		badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Too many user metadata key value pairs")
		return badRequest
	}

	for name, value := range secret.UserMetadata {
		if len(name) > MaxCharLenForMetadata {
			badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": User metadata key too long")
			return badRequest
		}
		if containsReservedCharacter(name) {
			badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": User metadata key " + ContainsReservedCharacterMessage)
			return badRequest
		}
		if len(value) > MaxCharLenForMetadata {
			badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": User metadata value too long")
			return badRequest
		}
	}

	return nil
}

// Post performs steps to create a secret. It implements Service.
// We need to do the following:
// 1.  Create the HSM backed secret.  If a payload exists, use Barbian /v1/secrets.
// 2.  Store the secret
// For any errors on storage, we need to delete the secret created in step 1 and return with 5xx status error.
func (svc *basicService) Post(_ context.Context, request *communications.SecretRequest) (*communications.SecretsResponse, error) {
	headers := request.Headers
	if headers == nil {
		badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Requires Headers")
		svc.logger.Log("err", badRequest.Error(), "correlation_id", headers.CorrelationID)
		return nil, badRequest
	}

	secret := request.Secret
	//Required for new API-created secrets to be deletable from UI
	secret.Name = strings.TrimSpace(secret.Name)
	if validationErr := validateSecret(secret); validationErr != nil {
		svc.logger.Log("err", validationErr.Error(), "correlation_id", headers.CorrelationID)
		return nil, validationErr
	}

	var includeResource bool
	parameters := request.Parameters
	if parameters != nil {
		includeResource = parameters.IncludeResource
	}

	createTransaction := transactions.NewTransaction()
	defer createTransaction.Complete()

	secretService, errNewStrat := keystore.NewKeystore(svc.backEndKeystore, headers, svc.logger)
	if errNewStrat != nil {
		return nil, errNewStrat
	}

	id, errCreate := secretService.CreateSecret(secret, &createTransaction)
	if errCreate != nil {
		svc.cleanupFailure(&createTransaction, headers.CorrelationID)
		return nil, errCreate
	}

	secret.SetID(id)
	secret.CreationDate = time.Now().UTC().Format(time.RFC3339)

	// <2> Store the secret

	conn, err := grpc.Dial(dbServerPath, grpc.WithInsecure(), grpc.WithTimeout(time.Second*time.Duration(timeout)))
	if err != nil {
		svc.cleanupFailure(&createTransaction, headers.CorrelationID)
		svc.logger.Log("err", err.Error(), "correlation_id", headers.CorrelationID)
		return nil, err
	}
	defer conn.Close()

	dbClient := client.NewClient(conn, log.NewNopLogger())
	dbRequest := communications.NewSecretRequest()
	dbRequest.SetHeaders(headers)
	dbRequest.SetSecret(secret)

	dbResponse, errDbResponse := dbClient.Create(context.Background(), dbRequest)
	if errDbResponse != nil {
		svc.cleanupFailure(&createTransaction, headers.CorrelationID)
		svc.logger.Log("err", errDbResponse.Error(), "correlation_id", headers.CorrelationID)
		return nil, errDbResponse
	}

	// No rollback for Metadata failure since there is no other functionality after
	// If additional functionality, need to
	payload := ""
	if *secret.Extractable != false {
		payload = secret.Payload
	}

	returnedSecret := dbResponse.Secrets[0]

	if returnedSecret.State == secrets.Activation {
		returnedSecret.SetPayload(payload)
	}

	createResponse := communications.NewSecretsResponse()

	if !includeResource {
		//Needed for legacy API-created secrets to be deletable in UI
		newSecret := secrets.NewSecret()
		newSecret.SetName(strings.TrimSpace(returnedSecret.Name))
		newSecret.SetID(returnedSecret.ID)
		newSecret.SetState(returnedSecret.State)
		createResponse.AppendSecret(newSecret)
		return createResponse, nil
	}

	createResponse.AppendSecret(returnedSecret)
	return createResponse, nil
}

// Actions performs steps to actions by a secret.
func (svc *basicService) Actions(_ context.Context, request *corecomms.SecretActionRequest) (*corecomms.SecretActionResponse, error) {
	return nil, errors.New(http.StatusText(http.StatusNotImplemented) + ": Action by secret not implemented")
}

func (svc *basicService) Get(ctx context.Context, request *communications.IDRequest) (*communications.SecretsResponse, error) {
	headers := request.Headers
	if headers == nil {
		badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Requires Headers")
		svc.logger.Log("err", badRequest.Error(), "correlation_id", headers.CorrelationID)
		return nil, badRequest
	}

	id := request.ID
	if id == "" {
		badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Requires ID")
		svc.logger.Log("err", badRequest.Error(), "correlation_id", headers.CorrelationID)
		return nil, badRequest
	}

	conn, err := grpc.Dial(dbServerPath, grpc.WithInsecure(), grpc.WithTimeout(time.Second*time.Duration(timeout)))
	if err != nil {
		svc.logger.Log("err", err.Error(), "correlation_id", headers.CorrelationID)
		return nil, err
	}
	defer conn.Close()

	client := client.NewClient(conn, log.NewNopLogger())
	getRequest := communications.NewIDRequest()
	getRequest.SetHeaders(headers)
	getRequest.SetID(id)

	//TODO ARS need to add the parallel operations back in
	dbResponse, errDbResponse := client.Get(ctx, getRequest)
	if errDbResponse != nil {
		svc.logger.Log("err", errDbResponse.Error(), "correlation_id", headers.CorrelationID)
		return nil, errDbResponse
	}

	if dbResponse.Secrets == nil || len(dbResponse.Secrets) == 0 || dbResponse.Secrets[0] == nil {
		notFoundErr := errors.New(http.StatusText(http.StatusNotFound) + ": Unable to find secret with given ID")
		svc.logger.Log("err", notFoundErr.Error(), "correlation_id", headers.CorrelationID)
		return nil, notFoundErr
	}

	secretService, errNewStrat := keystore.NewKeystore(svc.backEndKeystore, headers, svc.logger)
	if errNewStrat != nil {
		return nil, errNewStrat
	}

	var payload string
	var barbicanState secrets.KeyStates
	var errPayload error
	payload, barbicanState, errPayload = secretService.GetPayload(id)

	//Check if the secret has already been marked an error.
	metadata := dbResponse.Secrets[0]
	if metadata.State == secrets.Destroyed {
		return dbResponse, nil
	}

	if errPayload != nil {
		errPayload = errors.New("Unable to retrieve secret payload. Please try again without Prefer header.")
		svc.logger.Log("err", errPayload.Error(), "correlation_id", headers.CorrelationID)
		return nil, errPayload
	}

	if metadata.State != secrets.Destroyed && errPayload != nil {
		return nil, errPayload
	}

	if (barbicanState == secrets.Destroyed) || (barbicanState != metadata.State) {
		updateRequest := communications.NewUpdateRequest()
		updateRequest.SetHeaders(headers)
		updateRequest.SetID(id)

		//A state of destroyed from barbican means that secret creation failed.
		if barbicanState == secrets.Destroyed {
			err = handleFailedGeneration(id, metadata, client, updateRequest)
			if err != nil {
				return nil, err
			}
		} else if barbicanState != metadata.State {
			updates := map[string]string{"state": strconv.Itoa(int(barbicanState)),
				"nonactive_state_reason": strconv.Itoa(int(getReason(barbicanState)))}
			updateRequest.SetUpdates(updates)

			_, err = client.Update(context.Background(), updateRequest)
			if err != nil {
				return nil, err
			}
			dbResponse.Secrets[0].State = barbicanState
		}
	}

	if barbicanState == secrets.Activation {
		if *dbResponse.Secrets[0].Extractable == false {
			dbResponse.Secrets[0].Payload = ""
		} else {
			dbResponse.Secrets[0].Payload = payload
		}
	}

	return dbResponse, nil
}

func (svc *basicService) Head(ctx context.Context, request *communications.BaseRequest) (*communications.NumberResponse, error) {
	headers := request.Headers
	if headers == nil {
		badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Requires Headers")
		svc.logger.Log("err", badRequest.Error(), "correlation_id", headers.CorrelationID)
		return nil, badRequest
	}

	parameters := request.Parameters
	if parameters == nil {
		badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Requires Parameters")
		svc.logger.Log("err", badRequest.Error(), "correlation_id", headers.CorrelationID)
		return nil, badRequest
	}

	conn, err := grpc.Dial(dbServerPath, grpc.WithInsecure(), grpc.WithTimeout(time.Second*time.Duration(timeout)))
	if err != nil {
		svc.logger.Log("err", err.Error(), "correlation_id", headers.CorrelationID)
		return nil, err
	}
	defer conn.Close()

	client := client.NewClient(conn, log.NewNopLogger())
	headRequest := communications.NewBaseRequest()
	headRequest.SetHeaders(headers)
	headRequest.SetParameters(parameters)

	dbResponse, errDbResponse := client.GetTotal(ctx, headRequest)
	if errDbResponse != nil {
		svc.logger.Log("err", errDbResponse.Error(), "correlation_id", headers.CorrelationID)
		return nil, errDbResponse
	}

	return dbResponse, nil
}

func (svc *basicService) List(ctx context.Context, request *communications.BaseRequest) (*communications.SecretsResponse, error) {
	headers := request.Headers
	if headers == nil {
		badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Requires Headers")
		svc.logger.Log("err", badRequest.Error(), "correlation_id", headers.CorrelationID)
		return nil, badRequest
	}

	parameters := request.Parameters
	if parameters == nil {
		badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Requires Parameters")
		svc.logger.Log("err", badRequest.Error(), "correlation_id", headers.CorrelationID)
		return nil, badRequest
	}

	conn, err := grpc.Dial(dbServerPath, grpc.WithInsecure(), grpc.WithTimeout(time.Second*time.Duration(timeout)))
	if err != nil {
		svc.logger.Log("err", err.Error(), "correlation_id", headers.CorrelationID)
		return nil, err
	}
	defer conn.Close()

	client := client.NewClient(conn, log.NewNopLogger())
	listRequest := communications.NewBaseRequest()
	listRequest.SetHeaders(headers)
	listRequest.SetParameters(parameters)

	dbResponse, errDbResponse := client.List(ctx, listRequest)
	if errDbResponse != nil {
		svc.logger.Log("err", errDbResponse.Error(), "correlation_id", headers.CorrelationID)
		return nil, errDbResponse
	}

	inactives := getInactiveKeys(dbResponse.Secrets)
	if len(inactives) != 0 {
		updateRequest := communications.NewUpdateRequest()
		updateRequest.SetHeaders(headers)

		secretService, errNewStrat := keystore.NewKeystore(svc.backEndKeystore, headers, svc.logger)
		if errNewStrat != nil {
			return nil, errNewStrat
		}

		checkStatus(inactives, client, updateRequest, secretService)
		dbResponse.Secrets = filterErroredKeys(dbResponse.Secrets)
	}

	return dbResponse, nil
}

func (svc *basicService) Delete(_ context.Context, request *communications.IDRequest) (*communications.SecretsResponse, error) {
	headers := request.Headers
	if headers == nil {
		badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Requires Headers")
		svc.logger.Log("err", badRequest.Error(), "correlation_id", headers.CorrelationID)
		return nil, badRequest
	}

	id := request.ID
	if id == "" {
		badRequest := errors.New(http.StatusText(http.StatusBadRequest) + ": Requires ID")
		svc.logger.Log("err", badRequest.Error(), "correlation_id", headers.CorrelationID)
		return nil, badRequest
	}

	var includeResource bool
	parameters := request.Parameters
	if parameters != nil {
		includeResource = parameters.IncludeResource
	}

	secretService, errNewStrat := keystore.NewKeystore(svc.backEndKeystore, headers, svc.logger)
	if errNewStrat != nil {
		return nil, errNewStrat
	}

	//TODO: csolis - 11/10/2016 - Rollback for delete is dark until cassandra db
	// Has been added and new APIs can be rewritten to make sure full rollback can occur.
	// Transaction is simply created and closed since some function definitions now require it.
	createTransaction := transactions.NewTransaction()
	defer createTransaction.Complete()

	conn, errGet := grpc.Dial(dbServerPath, grpc.WithInsecure(), grpc.WithTimeout(time.Second*time.Duration(timeout)))
	if errGet != nil {
		svc.logger.Log("err", errGet.Error(), "correlation_id", headers.CorrelationID)
		return nil, errGet
	}
	defer conn.Close()

	//Fetch the payload - just incase the user wants the whole secret returned.
	var payload string
	var state secrets.KeyStates
	var errPayload error
	if includeResource {
		for i := 0; i < MaxRetries; i++ {
			payload, state, errPayload = secretService.GetPayload(id)
			if errPayload == nil && state != secrets.Preactivation {
				break
			}
		}
		if errPayload != nil {
			svc.logger.Log("err", errPayload.Error(), "correlation_id", headers.CorrelationID)
			errPayload = errors.New("Unable to retrieve secret payload. Please try again without Prefer header.")
			return nil, errPayload
		}

		if state == secrets.Preactivation {
			errPreactive := errors.New(http.StatusText(http.StatusConflict) + ": Unable to delete secret while key is still generating.")
			svc.logger.Log("err", errPreactive.Error(), "correlation_id", headers.CorrelationID)
			return nil, errPreactive
		}
	}

	//Step 1 - Delete secret material
	errDelete := secretService.DeleteSecret(id, &createTransaction)
	if errDelete != nil {
		//svc.cleanupFailure(&createTransaction, headers.CorrelationID)
		svc.logger.Log("err", errDelete.Error(), "correlation_id", headers.CorrelationID)
		return nil, errDelete
	}

	// Clients for requests
	client := client.NewClient(conn, log.NewNopLogger())
	idRequest := communications.NewIDRequest()
	idRequest.SetHeaders(headers)
	idRequest.SetID(id)

	//Step 2 - Set the metadata to show that the material has been destroyed.
	dbDeleteResponse, errDbDeleteResponse := client.Delete(context.Background(), idRequest)
	if errDbDeleteResponse != nil {
		//svc.cleanupFailure(&createTransaction, headers.CorrelationID)
		svc.logger.Log("err", errDbDeleteResponse.Error(), "correlation_id", headers.CorrelationID)
		return nil, errDbDeleteResponse
	}

	deleteResponse := communications.NewSecretsResponse()

	var returnSecret *secrets.Secret
	if includeResource {
		if dbDeleteResponse.Secrets == nil || len(dbDeleteResponse.Secrets) == 0 || dbDeleteResponse.Secrets[0] == nil {
			notFoundErr := errors.New(http.StatusText(http.StatusNotFound) + ": Unable to find secret with given ID")
			svc.logger.Log("err", notFoundErr.Error(), "correlation_id", headers.CorrelationID)
			return nil, notFoundErr
		}

		returnSecret = dbDeleteResponse.Secrets[0]
		if *returnSecret.Extractable == false {
			returnSecret.Payload = ""
			deleteResponse.AppendSecret(returnSecret)
		} else {
			returnSecret.Payload = payload
			deleteResponse.AppendSecret(returnSecret)
		}
	}

	return deleteResponse, nil
}

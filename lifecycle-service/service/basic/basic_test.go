// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package basic

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/kit/log"

	"context"

	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/keystore"
	configuration "github.ibm.com/Alchemy-Key-Protect/kp-go-config"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/secrets"
)

var once sync.Once

// Vars and consts needed for the random string generation function
var src = rand.NewSource(time.Now().UnixNano())

const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits

	letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

var (
	backEndStrategy keystore.Type
	logger          log.Logger
)

func init() {
	backEndStrategy = keystore.Mock

	logger = log.NewLogfmtLogger(os.Stderr)
	logger = log.With(logger, "ts", log.DefaultTimestampUTC,
		"service", "gRPC Secret BasicService",
		"caller", log.DefaultCaller)
}

// Taken from http://stackoverflow.com/a/31832326/2109566
func RandString(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

// when all the tests that work run, coverage goes from 3.2 percent to 12.7

func TestCreateSecret(t *testing.T) {
	t.SkipNow()
	// requires db-server running in test mode to pass.

	svc := Service(logger, backEndStrategy)

	testRequest := communications.NewSecretRequest()
	headers := &communications.Headers{
		Authorization: "Bearer 1234",
		BluemixSpace:  "space-1234",
		BluemixOrg:    "org-1234",
		CorrelationID: "123456789",
		UserID:        "MyUser",
	}
	testRequest.SetHeaders(headers)

	dummySecret := secrets.NewSecret()
	dummySecret.Payload = "my secret payload"
	testRequest.SetSecret(dummySecret)

	_, errCreate := svc.Post(context.Background(), testRequest)
	if errCreate != nil {
		t.Error(errCreate)
	}
}

type metadataValidationTest struct {
	secret *secrets.Secret
	pass   bool
}

var metadataValidationTests = []metadataValidationTest{
	{
		&secrets.Secret{
			Name:        "hi",
			Description: "working secret",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Tags: []string{"a", "b", "c", "d"},
		},
		true,
	},
	{
		&secrets.Secret{
			Name:        "hi",
			Description: "has no tags",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
		},
		true,
	},
	{
		&secrets.Secret{
			Name:        "hi",
			Description: "too many tags",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Tags: []string{"a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d"},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "hi",
			Description: "max tags",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Tags: []string{"a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b"},
		},
		true,
	},
	{
		&secrets.Secret{
			Name:        "hi",
			Description: "has long tags",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Tags: []string{"a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "11111111222222223333333344444444", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b"},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "hi",
			Description: "has max tags and one tag at max length",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Tags: []string{"a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "111111112222222233333333444444", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b"},
		},
		true,
	},
	{
		&secrets.Secret{
			Name:        "hi",
			Description: "has invalid tag character | ",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Tags: []string{"a", "b", "c", "d", "a", "|", "c", "d", "a", "b", "c", "d", "a", "111111112222222233333333444444", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b"},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "hi",
			Description: "has invalid tag character > ",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Tags: []string{"a", "b", "c", "d", "a", ">", "c", "d", "a", "b", "c", "d", "a", "111111112222222233333333444444", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b"},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "hi",
			Description: "has invalid tag character < ",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Tags: []string{"a", "b", "c", "d", "a", "<", "c", "d", "a", "b", "c", "d", "a", "111111112222222233333333444444", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b"},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "hi",
			Description: "has invalid tag character &",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Tags: []string{"a", "b", "c", "d", "a", "&", "c", "d", "a", "b", "c", "d", "a", "111111112222222233333333444444", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b"},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "hi",
			Description: "has invalid tag character :",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Tags: []string{"a", "b", "c", "d", "a", ":", "c", "d", "a", "b", "c", "d", "a", "111111112222222233333333444444", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b"},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "hi",
			Description: "has allowed but odd tag characters ",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Tags: []string{"=", "+", "\\", "/", "~", "!", "%", "5", "-", "_", "^", "GGG", "a", "111111112222222233333333444444", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b", "c", "d", "a", "b"},
		},
		true,
	},
	{
		&secrets.Secret{
			Name:        "hi",
			Description: "bad date",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: "silly date",
			},
			Tags: []string{"a", "b", "c", "d"},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "hi",
			Description: "date wrong format",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC1123),
			},
			Tags: []string{"a", "b", "c", "d"},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "hi",
			Description: "empty date",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: "",
			},
			Tags: []string{"a", "b", "c", "d"},
		},
		true,
	},
	{
		&secrets.Secret{
			Name:        "hi",
			Description: "missing date",
			Tags:        []string{"a", "b", "c", "d"},
		},
		true,
	},
	{
		&secrets.Secret{
			Name:        "h",
			Description: "name too short",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},

			Tags: []string{"a", "b", "c", "d"},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        RandString(231),
			Description: "name too long",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},

			Tags: []string{"a", "b", "c", "d"},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        RandString(230),
			Description: "name at max",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},

			Tags: []string{"a", "b", "c", "d"},
		},
		true,
	},
	{
		&secrets.Secret{
			Name:        "description too long",
			Description: RandString(231),
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},

			Tags: []string{"a", "b", "c", "d"},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "description at max",
			Description: RandString(230),
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},

			Tags: []string{"a", "b", "c", "d"},
		},
		true,
	},
	{
		&secrets.Secret{
			Name:        "payload at max",
			Description: "max payload",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(10000),

			Tags: []string{"a", "b", "c", "d"},
		},
		true,
	},
	{
		&secrets.Secret{
			Name:        "payload too long",
			Description: "max payload",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(10001),

			Tags: []string{"a", "b", "c", "d"},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "valid algorithm metadata",
			Description: "normal",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(100),

			Tags: []string{"a", "b", "c", "d"},
			AlgorithmMetadata: map[string]string{
				"a": "b",
				"c": "d",
			},
		},
		true,
	},
	{
		&secrets.Secret{
			Name:        "too many key, value pairs in algorithm metadata",
			Description: "too much algorithm metadata",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(100),

			Tags: []string{"a", "b", "c", "d"},
			AlgorithmMetadata: map[string]string{"1": "1", "2": "2", "3": "3", "4": "4", "5": "5", "6": "6", "7": "7", "8": "8", "9": "9",
				"10": "10", "11": "11", "12": "12", "13": "13", "14": "14", "15": "15", "16": "16", "17": "17", "18": "18", "19": "19",
				"20": "20", "21": "21", "22": "22", "23": "23", "24": "24", "25": "25", "26": "26", "27": "27", "28": "28", "29": "29",
				"30": "30", "31": "31",
			},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "limit key, value pairs in algorithm metadata",
			Description: "hit algorithm metadata limit",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(100),

			Tags: []string{"a", "b", "c", "d"},
			AlgorithmMetadata: map[string]string{"1": "1", "2": "2", "3": "3", "4": "4", "5": "5", "6": "6", "7": "7", "8": "8", "9": "9",
				"10": "10", "11": "11", "12": "12", "13": "13", "14": "14", "15": "15", "16": "16", "17": "17", "18": "18", "19": "19",
				"20": "20", "21": "21", "22": "22", "23": "23", "24": "24", "25": "25", "26": "26", "27": "27", "28": "28", "29": "29",
				"30": "30",
			},
		},
		true,
	},
	{
		&secrets.Secret{
			Name:        "over max key in algorithm metadata",
			Description: "too many chars in key",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(100),

			Tags: []string{"a", "b", "c", "d"},
			AlgorithmMetadata: map[string]string{
				RandString(131): "1",
				"2":             "2",
				"3":             "3",
			},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "limit key in algorithm metadata",
			Description: "allowed limit chars in key",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(100),

			Tags: []string{"a", "b", "c", "d"},
			AlgorithmMetadata: map[string]string{
				RandString(130): "1",
				"2":             "2",
				"3":             "3",
			},
		},
		true,
	},
	{
		&secrets.Secret{
			Name:        "over max value in algorithm metadata",
			Description: "too many chars in value",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(100),

			Tags: []string{"a", "b", "c", "d"},
			AlgorithmMetadata: map[string]string{
				"1": RandString(131),
				"2": "2",
				"3": "3",
			},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "limit value in algorithm metadata",
			Description: "allowed limit chars in value",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(100),

			Tags: []string{"a", "b", "c", "d"},
			AlgorithmMetadata: map[string]string{
				"1": RandString(130),
				"2": "2",
				"3": "3",
			},
		},
		true,
	},

	{
		&secrets.Secret{
			Name:        "valid user metadata",
			Description: "normal",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(100),

			Tags: []string{"a", "b", "c", "d"},
			UserMetadata: map[string]string{
				"a": "b",
				"c": "d",
			},
		},
		true,
	},
	{
		&secrets.Secret{
			Name:        "too many key, value pairs in user metadata",
			Description: "too much user metadata",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(100),

			Tags: []string{"a", "b", "c", "d"},
			UserMetadata: map[string]string{"1": "1", "2": "2", "3": "3", "4": "4", "5": "5", "6": "6", "7": "7", "8": "8", "9": "9",
				"10": "10", "11": "11", "12": "12", "13": "13", "14": "14", "15": "15", "16": "16", "17": "17", "18": "18", "19": "19",
				"20": "20", "21": "21", "22": "22", "23": "23", "24": "24", "25": "25", "26": "26", "27": "27", "28": "28", "29": "29",
				"30": "30", "31": "31",
			},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "limit key, value pairs in user metadata",
			Description: "hit user metadata limit",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(100),

			Tags: []string{"a", "b", "c", "d"},
			UserMetadata: map[string]string{"1": "1", "2": "2", "3": "3", "4": "4", "5": "5", "6": "6", "7": "7", "8": "8", "9": "9",
				"10": "10", "11": "11", "12": "12", "13": "13", "14": "14", "15": "15", "16": "16", "17": "17", "18": "18", "19": "19",
				"20": "20", "21": "21", "22": "22", "23": "23", "24": "24", "25": "25", "26": "26", "27": "27", "28": "28", "29": "29",
				"30": "30",
			},
		},
		true,
	},
	{
		&secrets.Secret{
			Name:        "over max key in user metadata",
			Description: "too many chars in key",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(100),

			Tags: []string{"a", "b", "c", "d"},
			UserMetadata: map[string]string{
				RandString(131): "1",
				"2":             "2",
				"3":             "3",
			},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "limit key in user metadata",
			Description: "allowed limit chars in key",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(100),

			Tags: []string{"a", "b", "c", "d"},
			UserMetadata: map[string]string{
				RandString(130): "1",
				"2":             "2",
				"3":             "3",
			},
		},
		true,
	},
	{
		&secrets.Secret{
			Name:        "over max value in user metadata",
			Description: "too many chars in value",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(100),

			Tags: []string{"a", "b", "c", "d"},
			UserMetadata: map[string]string{
				"1": RandString(131),
				"2": "2",
				"3": "3",
			},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "limit value in user metadata",
			Description: "allowed limit chars in value",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(100),

			Tags: []string{"a", "b", "c", "d"},
			UserMetadata: map[string]string{
				"1": RandString(130),
				"2": "2",
				"3": "3",
			},
		},
		true,
	},
	{
		&secrets.Secret{
			Name:        "check reserved characters",
			Description: "left angle bracket not allowed",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(100),

			Tags: []string{"a", "b", "c", "d"},
			UserMetadata: map[string]string{
				"key<": "value",
			},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "check reserved characters",
			Description: "right angle bracket not allowed",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(100),

			Tags: []string{"a", "b", "c", "d"},
			UserMetadata: map[string]string{
				"key>": "value",
			},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "check reserved characters",
			Description: "colon not allowed",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(100),

			Tags: []string{"a", "b", "c", "d"},
			UserMetadata: map[string]string{
				"key:": "value",
			},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "check reserved characters",
			Description: "ampersand not allowed",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(100),

			Tags: []string{"a", "b", "c", "d"},
			UserMetadata: map[string]string{
				"key&": "value",
			},
		},
		false,
	},
	{
		&secrets.Secret{
			Name:        "check reserved characters",
			Description: "vertical pipe not allowed",
			CryptoPeriod: &secrets.CryptoPeriod{
				ExpirationDate: time.Now().UTC().Format(time.RFC3339),
			},
			Payload: RandString(100),

			Tags: []string{"a", "b", "c", "d"},
			UserMetadata: map[string]string{
				"key|": "value",
			},
		},
		false,
	},
}

func TestCreateValidation(t *testing.T) {
	configuration.Get().Set("feature_toggles.encrypt_metadata", true)
	configuration.Get().Set("feature_toggles.encrypt_user_metadata", true)

	testRequest := communications.NewSecretRequest()
	headers := &communications.Headers{
		Authorization: "Bearer 1234",
		BluemixSpace:  "space-1234",
		BluemixOrg:    "org-1234",
		CorrelationID: "123456789",
		UserID:        "MyUser",
	}

	testRequest.SetHeaders(headers)

	for _, test := range metadataValidationTests {
		dummySecret := secrets.NewSecret()
		if test.secret.Payload != "" {
			dummySecret.Payload = test.secret.Payload
		} else {
			dummySecret.Payload = "my secret payload"
		}
		if test.secret.CryptoPeriod != nil {
			dummySecret.ExpirationDate = test.secret.ExpirationDate
		}
		if len(test.secret.Tags) > 0 {
			dummySecret.Tags = test.secret.Tags
		}

		dummySecret.Name = test.secret.Name
		dummySecret.Description = test.secret.Description

		if len(test.secret.AlgorithmMetadata) > 0 {
			dummySecret.AlgorithmMetadata = test.secret.AlgorithmMetadata
		}

		if len(test.secret.UserMetadata) > 0 {
			dummySecret.UserMetadata = test.secret.UserMetadata
		}

		validationErr := validateSecret(dummySecret)
		if test.pass == true && validationErr != nil {
			t.Error(validationErr)
		}
		if test.pass == false && validationErr == nil {
			t.Error(validationErr)
		}

	}
}

func TestCreateSecretIncludeResource(t *testing.T) {
	t.SkipNow()
	// requires db-server running in test mode to pass.

	svc := Service(logger, backEndStrategy)

	testRequest := communications.NewSecretRequest()
	headers := &communications.Headers{
		Authorization: "Bearer 1234",
		BluemixSpace:  "space-1234",
		BluemixOrg:    "org-1234",
		CorrelationID: "123456789",
		UserID:        "MyUser",
	}
	testRequest.SetHeaders(headers)

	dummySecret := secrets.NewSecret()
	dummySecret.Payload = "my secret payload"
	testRequest.SetSecret(dummySecret)
	testRequest.SetIncludeResourceParameter(true)

	response, errCreate := svc.Post(context.Background(), testRequest)
	if errCreate != nil {
		t.Error(errCreate)
	}

	fmt.Println(response)
	if response.Secrets == nil || len(response.Secrets) == 0 || response.Secrets[0] == nil {
		t.Fail()
	}
}

func TestDeleteSecret(t *testing.T) {
	t.SkipNow()
	// requires db-server running in test mode to pass.

	svc := Service(logger, backEndStrategy)

	testRequestCreate := communications.NewSecretRequest()
	headers := &communications.Headers{
		Authorization: "Bearer 1234",
		BluemixSpace:  "space-1234",
		BluemixOrg:    "org-1234",
		CorrelationID: "123456789",
		UserID:        "MyUser",
	}
	testRequestCreate.SetHeaders(headers)

	dummySecret := secrets.NewSecret()
	dummySecret.Payload = "my secret payload"
	testRequestCreate.SetSecret(dummySecret)

	response, errCreate := svc.Post(context.Background(), testRequestCreate)
	if errCreate != nil {
		t.Error(errCreate)
	}

	if response.Secrets == nil || len(response.Secrets) == 0 || response.Secrets[0] == nil {
		t.Fail()
	}

	id := response.Secrets[0].ID

	testRequestDelete := communications.NewIDRequest()
	testRequestDelete.SetID(id)
	testRequestDelete.SetHeaders(headers)

	_, errDel := svc.Delete(context.Background(), testRequestDelete)
	if errDel != nil {
		t.Error(errDel)
	}
}

func TestDeleteSecretIncludeResource(t *testing.T) {
	t.SkipNow()
	// This one is failing because it needs to return the secret payload, which requires the core service

	svc := Service(logger, backEndStrategy)

	testRequestCreate := communications.NewSecretRequest()
	headers := &communications.Headers{
		Authorization: "Bearer 1234",
		BluemixSpace:  "space-1234",
		BluemixOrg:    "org-1234",
		CorrelationID: "123456789",
		UserID:        "MyUser",
	}
	testRequestCreate.SetHeaders(headers)

	dummySecret := secrets.NewSecret()
	dummySecret.Payload = "my secret payload"
	testRequestCreate.SetSecret(dummySecret)

	response, errCreate := svc.Post(context.Background(), testRequestCreate)
	if errCreate != nil {
		t.Error(errCreate)
	}

	if response.Secrets == nil || len(response.Secrets) == 0 || response.Secrets[0] == nil {
		t.Fail()
	}

	id := response.Secrets[0].ID

	testRequestDelete := communications.NewIDRequest()
	testRequestDelete.SetID(id)
	testRequestDelete.SetHeaders(headers)
	testRequestDelete.SetIncludeResourceParameter(true)

	responseDel, errDel := svc.Delete(context.Background(), testRequestDelete)
	if errDel != nil {
		t.Error(errDel)
	}

	fmt.Println(responseDel)
	if responseDel.Secrets == nil || len(responseDel.Secrets) == 0 || responseDel.Secrets[0] == nil {
		t.Fail()
	}
}

func TestCreateFailOnBarbicanSecretCreate(t *testing.T) {
	//Skip this test as it requires a db set up
	t.SkipNow()

	svc := Service(logger, backEndStrategy)

	// how to delete
	testRequest := communications.NewSecretRequest()
	headers := &communications.Headers{
		Authorization: "Bearer 1234",
		BluemixSpace:  "space-1234",
		BluemixOrg:    "org-1234",
		CorrelationID: "123456789",
	}
	testRequest.SetHeaders(headers)

	dummySecret := secrets.NewSecret()
	dummySecret.Payload = "my secret payload"
	testRequest.SetSecret(dummySecret)

	if _, err := svc.Post(nil, testRequest); err == nil {
		t.Errorf("Expecting error")
	}

}

func TestCreateFailOnMetadataCreate(t *testing.T) {
	//Skipping, this test requires a db.
	t.SkipNow()

	///SETUP BARBICAN BACKEND
	type barbicanSecret struct {
		SecretRef string `json:"secret_ref"`
	}

	dummyResponse, _ := json.Marshal(barbicanSecret{SecretRef: "999-99999-99999"})
	backendResponse := string(dummyResponse)
	const backendStatus = 201
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.Header.Get("x-openstack-request-id") == "" {
			t.Errorf("didn't get x-openstack-request-id header")
		}

		w.WriteHeader(backendStatus)
		w.Write([]byte(backendResponse))
	}))
	defer backend.Close()
	backendURL, barbicanBackendErr := url.Parse(backend.URL)
	if barbicanBackendErr != nil {
		t.Fatal(barbicanBackendErr)
	}
	fmt.Printf("backendURL: %v\n", backendURL) // TODO remove
	configuration.Get().Set("openstack.barbican.url", backendURL)
	///END SETUP BARBICAN BACKEND

	svc := Service(logger, backEndStrategy)

	// how to delete
	testRequest := communications.NewSecretRequest()
	headers := &communications.Headers{
		Authorization: "Bearer 1234",
		BluemixSpace:  "space-1234",
		BluemixOrg:    "org-1234",
		CorrelationID: "123456789",
	}
	testRequest.SetHeaders(headers)

	dummySecret := secrets.NewSecret()
	dummySecret.Payload = "my secret payload"
	testRequest.SetSecret(dummySecret)

	if _, err := svc.Post(nil, testRequest); err == nil {
		t.Errorf("Expecting error")
	}

}

func TestCreatePasses(t *testing.T) {
	t.Skip("skipping until figure out how to fake out db gRPC server backend")

	///SETUP BARBICAN BACKEND
	type barbicanSecret struct {
		SecretRef string `json:"secret_ref"`
	}

	dummyResponse, _ := json.Marshal(barbicanSecret{SecretRef: "999-99999-99999"})
	backendResponse := string(dummyResponse)
	const backendStatus = 201
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.Header.Get("x-openstack-request-id") == "" {
			t.Errorf("didn't get x-openstack-request-id header")
		}

		w.WriteHeader(backendStatus)
		w.Write([]byte(backendResponse))
	}))
	defer backend.Close()
	backendURL, barbicanBackendErr := url.Parse(backend.URL)
	if barbicanBackendErr != nil {
		t.Fatal(barbicanBackendErr)
	}
	fmt.Printf("backendURL: %v\n", backendURL) // TODO remove
	configuration.Get().Set("openstack.barbican.url", backendURL)
	///END SETUP BARBICAN BACKEND

	///SETUP DB BACKEND
	dbBackendResponse := "some dummy response"
	const dbBackendStatus = 201
	dbBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.WriteHeader(dbBackendStatus)
		w.Write([]byte(dbBackendResponse))
	}))
	defer dbBackend.Close()
	dbBackendURL, dbBackendErr := url.Parse(dbBackend.URL)
	if dbBackendErr != nil {
		t.Fatal(dbBackendErr)
	}
	fmt.Printf("backendURL: %v\n", dbBackendURL) // TODO remove
	hostInfo := strings.Split(dbBackendURL.Host, ":")
	fmt.Printf("port: %v\n", hostInfo[1]) // TODO remove
	configuration.Get().Set("dbService.ipv4_address", hostInfo[0])
	configuration.Get().Set("dbService.port", hostInfo[1])

	///END SETUP DB BACKEND

	svc := Service(logger, backEndStrategy)

	// how to delete
	testRequest := communications.NewSecretRequest()
	headers := &communications.Headers{
		Authorization: "Bearer 1234",
		BluemixSpace:  "space-1234",
		BluemixOrg:    "org-1234",
		CorrelationID: "123456789",
	}
	testRequest.SetHeaders(headers)

	dummySecret := secrets.NewSecret()
	dummySecret.Payload = "my secret payload"
	testRequest.SetSecret(dummySecret)

	if _, err := svc.Post(nil, testRequest); err != nil {
		t.Errorf("Unexpected error %v", err)
	}
}

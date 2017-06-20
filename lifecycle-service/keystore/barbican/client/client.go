// © Copyright 2016 IBM Corp. Licensed Materials – Property of IBM.

package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.ibm.com/Alchemy-Key-Protect/kp-go-consts"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
)

// constants used for package
const (
	CERTLOCATION = "/kp_data/config/ca.crt"
	HTTPS        = "https"

	// HTTPClientTimeout specifies the number of seconds the client should wait in seconds before canceling request
	HTTPClientTimeout = time.Second * 60
)

var certPool *x509.CertPool

func init() {
	caCert, err := ioutil.ReadFile(CERTLOCATION)
	if err != nil {
		certPool = nil
		return
	}
	certPool = x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCert)
}

// Client is an interface for making calls to Barbican
type Client interface {
	PostSecret(secret *PostSecretRequest) (ref string, err error)

	PostOrder(order *PostOrderRequest) (ref string, err error)

	CheckOrder(orderRef string) (*CheckOrderResponse, error)

	GetPayload(secretID string, accept string) (payload string, err error)

	DeleteOrder(orderRef string) error

	DeleteSecret(ID string) error
}

type barbicanClient struct {
	client       *http.Client
	barbicanHost string
	headers      *communications.Headers
}

// set base headers used for all requests
func basedHeaders(request *http.Request, clientHeaders *communications.Headers) {
	request.Header.Set(constants.AuthorizationHeader, clientHeaders.Authorization)
	request.Header.Set(constants.BluemixSpaceHeader, clientHeaders.BluemixSpace)
	request.Header.Set(constants.OpenstackRequestIDHeader, clientHeaders.CorrelationID)
}

// postRequest creates a request used for posts
func postRequest(body interface{}, url string) (request *http.Request, err error) {
	json, err := json.Marshal(body)
	if err != nil {
		return
	}

	request, err = http.NewRequest("POST", url, bytes.NewBuffer(json))
	if err != nil {
		return
	}

	return
}

//Get an ID out of a barbican URI
func parseRef(barbicanURI string) string {
	indx := strings.LastIndex(barbicanURI, "/")
	return barbicanURI[indx+1:]
}

func (client *barbicanClient) PostSecret(secret *PostSecretRequest) (string, error) {
	url := client.barbicanHost + SECRETS
	request, err := postRequest(secret, url)
	if err != nil {
		return "", err
	}

	// setup headers
	clientHeaders := client.headers
	basedHeaders(request, clientHeaders)
	request.Header.Set(constants.ContentTypeHeader, constants.AppJSONMime)

	response, err := client.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	return decoderPostSecretResponse(response)
}

func (client *barbicanClient) PostOrder(order *PostOrderRequest) (string, error) {
	url := client.barbicanHost + ORDERS
	request, err := postRequest(order, url)
	if err != nil {
		return "", err
	}

	// setup headers
	clientHeaders := client.headers
	basedHeaders(request, clientHeaders)
	request.Header.Set(constants.ContentTypeHeader, constants.AppJSONMime)

	response, err := client.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	return decoderPostOrderResponse(response)
}

func (client *barbicanClient) GetPayload(secretID string, accept string) (string, error) {
	if accept != constants.OctetStreamMime && accept != constants.TextPlainMime {
		return "", errors.New("Invalid accept header given")
	}
	url := client.barbicanHost + SECRETS + "/" + secretID + PAYLOAD
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	// setup headers
	clientHeaders := client.headers
	basedHeaders(request, clientHeaders)
	request.Header.Set(constants.AcceptHeader, accept)

	response, err := client.client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	return decodeGetPayloadResponse(response, accept)
}

func (client *barbicanClient) DeleteSecret(secretID string) error {
	url := client.barbicanHost + SECRETS + "/" + secretID
	request, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}

	// setup headers
	clientHeaders := client.headers
	basedHeaders(request, clientHeaders)

	response, err := client.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusNoContent {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return err
		}

		return decodeError(body)
	}

	return nil
}

func (client *barbicanClient) DeleteOrder(orderRef string) error {
	url := client.barbicanHost + ORDERS + "/" + orderRef
	request, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}

	// setup headers
	clientHeaders := client.headers
	basedHeaders(request, clientHeaders)
	request.Header.Set(constants.AcceptHeader, constants.AppJSONMime)

	response, err := client.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusNoContent {
		return errors.New("Unable to delete order")
	}

	return nil
}

func (client *barbicanClient) CheckOrder(orderRef string) (*CheckOrderResponse, error) {
	url := client.barbicanHost + ORDERS + "/" + orderRef
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// setup headers
	clientHeaders := client.headers
	basedHeaders(request, clientHeaders)
	request.Header.Set(constants.AcceptHeader, constants.AppJSONMime)

	response, err := client.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	return decoderCheckOrderResponse(response)
}

// NewClient will return a new barbican Client
func NewClient(barbicanHost string, headers *communications.Headers) Client {
	client := new(barbicanClient)
	client.client = &http.Client{
		Timeout: HTTPClientTimeout,
	}
	if strings.Contains(strings.ToLower(barbicanHost), strings.ToLower(HTTPS)) {
		if certPool == nil {
			panic("HTTPS is not configured.")
		}
		//https
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		}
		client.client.Transport = tr
	}
	client.barbicanHost = barbicanHost
	client.headers = headers
	return client
}

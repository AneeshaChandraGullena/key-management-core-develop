// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package analytics

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"context"

	segmentio "github.com/segmentio/analytics-go"

	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/definitions"
	corecomms "github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-config"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
)

type analyticsService struct {
	definitions.Service
	environment   string
	region        string
	segmentClient *segmentio.Client
}

const httpTimeout = 30

// Service returns a new instance of a analytics middleware.
func Service(env string, region string, proxy string, service definitions.Service) definitions.Service {
	client := segmentio.New(configuration.Get().GetString("analytics.key"))
	proxyURL, err := url.Parse(proxy)
	if err != nil {
		panic("Couldn't set up proxy for analytics")
	}
	client.Client = http.Client{Timeout: time.Second * time.Duration(httpTimeout), Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	return &analyticsService{service, env, region, client}
}

func (analyticsMiddleWare *analyticsService) Post(ctx context.Context, request *communications.SecretRequest) (*communications.SecretsResponse, error) {
	headers := request.GetHeaders()

	userGUID := headers.UserID
	if userGUID == "" {
		return nil, errors.New(http.StatusText(http.StatusBadRequest) + ": Request requires User ID")
	}

	analyticsMiddleWare.segmentClient.Identify(&segmentio.Identify{
		UserId: userGUID,
	})

	eventDescription := configuration.Get().GetString("analytics.prefix") + "Created Secret"
	op := "uploaded"

	secret := request.Secret

	// an empty payload means the user is asking us to generate a secret for them
	if len(secret.Payload) == 0 {
		op = "generated"
	}
	usermetadata := false

	if len(secret.UserMetadata) > 0 {
		usermetadata = true
	}
	analyticsMiddleWare.segmentClient.Track(&segmentio.Track{
		Event:  eventDescription,
		UserId: userGUID,
		Properties: map[string]interface{}{
			"Environment": analyticsMiddleWare.environment,
			"Region":      analyticsMiddleWare.region,
			"Space":       headers.BluemixSpace,
			"Operation":   op,
			"Metadata":    usermetadata,
		},
	})

	return analyticsMiddleWare.Service.Post(ctx, request)
}

func (analyticsMiddleWare *analyticsService) Actions(ctx context.Context, request *corecomms.SecretActionRequest) (*corecomms.SecretActionResponse, error) {
	headers := request.GetHeaders()

	userGUID := headers.UserID
	if userGUID == "" {
		return nil, errors.New(http.StatusText(http.StatusBadRequest) + ": Request requires User ID")
	}

	analyticsMiddleWare.segmentClient.Identify(&segmentio.Identify{
		UserId: userGUID,
	})

	eventDescription := configuration.Get().GetString("analytics.prefix") + "Action by Secret"
	analyticsMiddleWare.segmentClient.Track(&segmentio.Track{
		Event:  eventDescription,
		UserId: userGUID,
		Properties: map[string]interface{}{
			"Environment": analyticsMiddleWare.environment,
			"Region":      analyticsMiddleWare.region,
			"Space":       headers.BluemixSpace,
		},
	})

	return analyticsMiddleWare.Service.Actions(ctx, request)
}

func (analyticsMiddleWare *analyticsService) Get(ctx context.Context, request *communications.IDRequest) (*communications.SecretsResponse, error) {
	headers := request.GetHeaders()

	userGUID := headers.UserID
	if userGUID == "" {
		return nil, errors.New(http.StatusText(http.StatusBadRequest) + ": Request requires User ID")
	}

	analyticsMiddleWare.segmentClient.Identify(&segmentio.Identify{
		UserId: userGUID,
	})

	eventDescription := configuration.Get().GetString("analytics.prefix") + "Retrieved Secret"
	analyticsMiddleWare.segmentClient.Track(&segmentio.Track{
		Event:  eventDescription,
		UserId: userGUID,
		Properties: map[string]interface{}{
			"Environment": analyticsMiddleWare.environment,
			"Region":      analyticsMiddleWare.region,
			"Space":       headers.BluemixSpace,
		},
	})

	return analyticsMiddleWare.Service.Get(ctx, request)
}

func (analyticsMiddleWare *analyticsService) Head(ctx context.Context, request *communications.BaseRequest) (*communications.NumberResponse, error) {
	headers := request.GetHeaders()

	userGUID := headers.UserID
	if userGUID == "" {
		return nil, errors.New(http.StatusText(http.StatusBadRequest) + ": Request requires User ID")
	}

	analyticsMiddleWare.segmentClient.Identify(&segmentio.Identify{
		UserId: userGUID,
	})

	eventDescription := configuration.Get().GetString("analytics.prefix") + "Head Secret"
	analyticsMiddleWare.segmentClient.Track(&segmentio.Track{
		Event:  eventDescription,
		UserId: userGUID,
		Properties: map[string]interface{}{
			"Environment": analyticsMiddleWare.environment,
			"Region":      analyticsMiddleWare.region,
			"Space":       headers.BluemixSpace,
		},
	})

	return analyticsMiddleWare.Service.Head(ctx, request)
}

func (analyticsMiddleWare *analyticsService) List(ctx context.Context, request *communications.BaseRequest) (*communications.SecretsResponse, error) {
	headers := request.GetHeaders()

	userGUID := headers.UserID
	if userGUID == "" {
		return nil, errors.New(http.StatusText(http.StatusBadRequest) + ": Request requires User ID")
	}

	analyticsMiddleWare.segmentClient.Identify(&segmentio.Identify{
		UserId: userGUID,
	})

	eventDescription := configuration.Get().GetString("analytics.prefix") + "List Secret"
	analyticsMiddleWare.segmentClient.Track(&segmentio.Track{
		Event:  eventDescription,
		UserId: userGUID,
		Properties: map[string]interface{}{
			"Environment": analyticsMiddleWare.environment,
			"Region":      analyticsMiddleWare.region,
			"Space":       headers.BluemixSpace,
		},
	})

	return analyticsMiddleWare.Service.List(ctx, request)
}

func (analyticsMiddleWare *analyticsService) Delete(ctx context.Context, request *communications.IDRequest) (*communications.SecretsResponse, error) {
	headers := request.GetHeaders()

	userGUID := headers.UserID
	if userGUID == "" {
		return nil, errors.New(http.StatusText(http.StatusBadRequest) + ": Request requires User ID")
	}

	analyticsMiddleWare.segmentClient.Identify(&segmentio.Identify{
		UserId: userGUID,
	})

	eventDescription := configuration.Get().GetString("analytics.prefix") + "Deleted Secret"
	analyticsMiddleWare.segmentClient.Track(&segmentio.Track{
		Event:  eventDescription,
		UserId: userGUID,
		Properties: map[string]interface{}{
			"Environment": analyticsMiddleWare.environment,
			"Region":      analyticsMiddleWare.region,
			"Space":       headers.BluemixSpace,
		},
	})

	return analyticsMiddleWare.Service.Delete(ctx, request)
}

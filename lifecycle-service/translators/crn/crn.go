// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package crn

import (
	"context"
	"crypto/md5" // #nosec
	"fmt"
	"io"
	"os"
	"strings"

	crngo "github.ibm.com/Alchemy-Key-Protect/crn-go-lib"
	constants "github.ibm.com/Alchemy-Key-Protect/kp-go-consts"
)

var hostname string

func init() {
	var err error
	if hostname == "" {
		hostname, err = os.Hostname()
		if err != nil {
			hostname = "localhost"
		}
	}
}

func getRegion(hostname string) string {
	var region string
	chunks := strings.Split(hostname, "-")
	if len(chunks) < 2 {
		region = "dal09"
	} else {
		region = chunks[1]
	}

	return region
}

func getCloudName(hostname string) string {
	var cloudName string
	env := strings.Split(hostname, "-")[0]
	switch env {
	case "prod":
		cloudName = "bluemix"
	default:
		cloudName = "staging"
	}
	return cloudName
}

func getServiceInstance(org, space string) string {
	h := md5.New() // #nosec
	io.WriteString(h, org)
	io.WriteString(h, space)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// GetCRN creates and returns CRN string using CRN go library
func GetCRN(ctx context.Context, resourceID string) (string, error) {
	var org, space string
	if ctx.Value(ContextKey(constants.BluemixOrgHeader)) != nil {
		org = ctx.Value(ContextKey(constants.BluemixOrgHeader)).(string)
	}

	if ctx.Value(ContextKey(constants.BluemixSpaceHeader)) != nil {
		space = ctx.Value(ContextKey(constants.BluemixSpaceHeader)).(string)
	}

	crnTemplate := crngo.Template{
		CloudName:       getCloudName(hostname),
		CloudType:       crngo.PublicCloudType,
		ServiceName:     "kms",
		Region:          getRegion(hostname),
		Scope:           crngo.BuildScope(crngo.SpaceScopePrefix, space),
		ServiceInstance: getServiceInstance(org, space),
		ResourceType:    "key",
		ResourceID:      resourceID,
	}

	crnObject, err := crngo.NewCRN(&crnTemplate)
	if err != nil {
		return "", err
	}

	return crnObject.GetRepresentation(), nil
}

// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package crn

import (
	"context"
	"net/http"
	"testing"

	crngo "github.ibm.com/Alchemy-Key-Protect/crn-go-lib"
	constants "github.ibm.com/Alchemy-Key-Protect/kp-go-consts"
)

var (
	bluemixOrg   = "testOrg"
	bluemixSpace = "testSpace"
)

func TestToHTTPContext(t *testing.T) {
	reqFunc := ToHTTPContext()
	ctx := reqFunc(context.Background(), &http.Request{})
	if ctx.Value(ContextKey(constants.BluemixSpaceHeader)) != nil {
		t.Errorf("wasn't expecting value in context, got: %s", ctx.Value(ContextKey(constants.BluemixSpaceHeader)).(string))
	}

	header := http.Header{}
	header.Set(constants.BluemixOrgHeader, bluemixOrg)
	header.Set(constants.BluemixSpaceHeader, bluemixSpace)
	ctx = reqFunc(context.Background(), &http.Request{Header: header})
	org := ctx.Value(ContextKey(constants.BluemixOrgHeader)).(string)
	space := ctx.Value(ContextKey(constants.BluemixSpaceHeader)).(string)
	if org != bluemixOrg {
		t.Errorf("invalid org; expecting: %s, got: %s", bluemixOrg, org)
	}
	if space != bluemixSpace {
		t.Errorf("invalid space; expecting: %s, got: %s", space, bluemixSpace)
	}
}

func TestGetRegion(t *testing.T) {
	hostname = "localhost"
	region := getRegion(hostname)
	if region != "dal09" {
		t.Errorf("invalid region, got: %s", region)
	}

	hostname = "staging-lon02-keyprotect-api-instance-domain"
	region = getRegion(hostname)
	if region != "lon02" {
		t.Errorf("invalid region, got: %s", region)
	}
}

func TestGetCloudName(t *testing.T) {
	hostname = "localhost"
	cloudName := getCloudName(hostname)
	if cloudName != "staging" {
		t.Errorf("invalid cloudName, got: %s", cloudName)
	}

	hostname = "prod-lon02-keyprotect-api-instance-domain"
	cloudName = getCloudName(hostname)
	if cloudName != "bluemix" {
		t.Errorf("invalid cloudName, got: %s", cloudName)
	}
}

func TestGetServiceInstance(t *testing.T) {
	org := "testOrg"
	space := "testSpace"
	md5Data := "e41912e31592ceffdc11903becd3cfcb"
	serviceInstance := getServiceInstance(org, space)
	if md5Data != serviceInstance {
		t.Errorf("expected: %s, got: %s", md5Data, serviceInstance)
	}
}

func TestGetCRN(t *testing.T) {
	hostname = "prod-lon02-keyprotect-api-instance-domain"
	reqFunc := ToHTTPContext()
	header := http.Header{}
	header.Set(constants.BluemixOrgHeader, bluemixOrg)
	header.Set(constants.BluemixSpaceHeader, bluemixSpace)
	ctx := reqFunc(context.Background(), &http.Request{Header: header})
	resourceID := "test-resource-identifier"
	crn, err := GetCRN(ctx, resourceID)
	if err != nil {
		t.Error(err)
	}

	crnObject, err := crngo.Parse(crn)
	if err != nil {
		t.Error(err)
	}

	region := crnObject.GetRegion()
	if region != "lon02" {
		t.Errorf("invalid region, got: %s", region)
	}

	resourceID = ""
	_, err = GetCRN(ctx, resourceID)
	if err == nil {
		t.Error("was expecting error, got nil")
	}
}

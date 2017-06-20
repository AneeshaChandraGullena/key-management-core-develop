// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package crn

import (
	"context"
	"net/http"

	kithttp "github.com/go-kit/kit/transport/http"
	constants "github.ibm.com/Alchemy-Key-Protect/kp-go-consts"
)

// ContextKey is a complex type string
// for defining context keys for CRN template
// https://github.com/golang/lint/pull/245
type ContextKey string

func (c ContextKey) String() string {
	return string(c)
}

var crnHeaders = []string{
	constants.BluemixOrgHeader,
	constants.BluemixSpaceHeader,
}

// ToHTTPContext sets values from HTTP header
// to HTTP context
func ToHTTPContext() kithttp.RequestFunc {
	return func(ctx context.Context, r *http.Request) context.Context {
		for _, header := range crnHeaders {
			val := r.Header.Get(header)
			if len(val) > 0 {
				ctx = context.WithValue(ctx, ContextKey(header), val)
			}
		}
		return ctx
	}
}

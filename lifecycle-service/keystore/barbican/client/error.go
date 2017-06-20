// © Copyright 2016 IBM Corp. Licensed Materials – Property of IBM.

package client

import "fmt"

// ErrorResponse is the standard barbican error response
type ErrorResponse struct {
	Message    string `json:"description"`
	Title      string `json:"title"`
	StatusCode int32  `json:"code"`
}

// Error will return an ErrorResponse in string Format
// Ensures that ErrorResponse meets the requirements for error interface
func (err *ErrorResponse) Error() string {
	return fmt.Sprintf("%s: %s", err.Title, err.Message)
}

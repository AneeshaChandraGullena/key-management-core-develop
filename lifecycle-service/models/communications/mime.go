// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package communications

// MIME types supported by Key Protect in Content-Type header
type MIME string

// exported mime types for Content-Type header
const (
	Secret MIME = "application/vnd.ibm.kms.secret+json"
	Key    MIME = "application/vnd.ibm.kms.key+json"
)

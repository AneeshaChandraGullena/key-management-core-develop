// © Copyright 2017 IBM Corp. Licensed Materials – Property of IBM.

package actions

// SecretAction is the main struct used for all secret actions
// wrap, unwrap
type SecretAction struct {
	Plaintext  string `json:"plaintext,omitempty"`
	Ciphertext string `json:"ciphertext,omitempty"`
	AAD        string `json:"aad,omitempty"`
}

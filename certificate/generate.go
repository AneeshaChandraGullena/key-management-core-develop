// This is a direct copy from go source: https://golang.org/src/crypto/tls/generate_cert.go
// because it's not a library, we've changed the main() to expose a 'generate' function for convenience.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Generate a self-signed X.509 certificate for a TLS server. Outputs to
// 'cert.pem' and 'key.pem' and will overwrite existing files.

package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

var (
	// original values
	// host       = flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
	// validFrom  = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
	// validFor   = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	// isCA       = flag.Bool("ca", false, "whether this cert should be its own Certificate Authority")
	// rsaBits    = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")
	// ecdsaCurve = flag.String("ecdsa-curve", "", "ECDSA curve to use to generate a key. Valid values are P224, P256, P384, P521")

	validFrom  = ""
	validFor   = 365 * 24 * time.Hour
	isCA       = true
	rsaBits    = 2048
	ecdsaCurve = ""
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) (*pem.Block, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}, nil
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
	default:
		return nil, nil
	}
}

// Exists checks if a cert and key have already been generated
func Exists(certPath string, keyPath string) error {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return err
	} else if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return err
	}
	return nil
}

// Generate makes a cert and key at specified path
func Generate(certPath string, keyPath string, host string) error {
	flag.Parse()

	if host == "" || certPath == "" || keyPath == "" {
		return fmt.Errorf("Missing required parameter host=[%s] certPath=[%s] keyPath=[%s]", host, certPath, keyPath)
	}

	var priv interface{}
	var err error
	switch ecdsaCurve {
	case "":
		priv, err = rsa.GenerateKey(rand.Reader, rsaBits)
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		err = fmt.Errorf("Unrecognized elliptic curve: %q", ecdsaCurve)
		log.Fatalf(err.Error())
		return err
	}
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
		return err
	}

	var notBefore time.Time
	if len(validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", validFrom)
		if err != nil {
			log.Fatalf("failed to parse creation date: %s", err)
			return err
		}
	}

	notAfter := notBefore.Add(validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Key Protect IBM Cloud"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		log.Fatalf("failed to open cert.pem for writing: %s", err)
		return err
	}
	err = certOut.Chmod(0400)
	if err != nil {
		log.Fatalf("failed to change permissions of cert.pem: %s", err)
		return err
	}
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		log.Fatalf("failed to encode contents of cert.pem: %s", err)
		return err
	}
	err = certOut.Close()
	if err != nil {
		log.Fatalf("failed to close cert.pem: %s", err)
		return err
	}
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0400)
	if err != nil {
		log.Fatalf("failed to open key.pem for writing: %s", err)
		return err
	}
	pemBlock, err := pemBlockForKey(priv)
	if err != nil {
		log.Fatalf("failed to marshal ECDSA private key: %s", err)
		return err
	}
	err = pem.Encode(keyOut, pemBlock)
	if err != nil {
		log.Fatalf("failed to encode key.pem: %s", err)
		return err
	}
	err = keyOut.Close()

	if err != nil {
		log.Fatalf("failed to close key.pem: %s", err)
		return err
	}
	return nil
}

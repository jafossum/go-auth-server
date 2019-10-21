package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/jafossum/go-auth-server/logger"
)

// RSA handling inspired by this GIST
// https://gist.github.com/jshap70/259a87a7146393aab5819873a193b88c

// ParseRsaKeys - Parse keys and validate, or generate a temporary pair
func ParseRsaKeys(rsaPrivKey, rsaPrivPass, rsaPubKey string) (*rsa.PrivateKey, error) {
	if rsaPrivKey == "" {
		logger.Warning.Println("No RSA Key given, generating temp one")
		return GenRsaKey(4096)
	}
	priv, err := ioutil.ReadFile(rsaPrivKey)
	if err != nil {
		logger.Warning.Println("No RSA private key found, generating temp one", nil)
		return GenRsaKey(4096)
	}
	privPem, _ := pem.Decode(priv)
	if privPem.Type != "RSA PRIVATE KEY" {
		logger.Warning.Println("RSA private key is of the wrong type: ", privPem.Type)
	}
	var privPemBytes []byte
	if rsaPrivPass != "" {
		privPemBytes, err = x509.DecryptPEMBlock(privPem, []byte(rsaPrivPass))
	} else {
		privPemBytes = privPem.Bytes
	}
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPemBytes); err != nil { // note this returns type `interface{}`
			logger.Error.Println("Unable to parse RSA private key, generating a temp one", err)
			return GenRsaKey(4096)
		}
	}
	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		logger.Error.Println("Unable to parse RSA private key, generating a temp one", err)
		return GenRsaKey(4096)
	}

	pub, err := ioutil.ReadFile(rsaPubKey)
	if err != nil {
		logger.Warning.Println("No RSA public key found, generating temp one", nil)
		return GenRsaKey(4096)
	}
	pubPem, _ := pem.Decode(pub)
	if pubPem == nil {
		logger.Error.Println("Use `ssh-keygen -f id_rsa.pub -e -m pem > id_rsa.pem` to generate the pem encoding of your RSA public key",
			fmt.Errorf("RSA public key not in pem format: %s", rsaPubKey))
		return GenRsaKey(4096)
	}
	if pubPem.Type != "RSA PUBLIC KEY" {
		logger.Warning.Println("RSA public key is of the wrong type: ", pubPem.Type)
		return GenRsaKey(4096)
	}
	if parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes); err != nil {
		logger.Error.Println("Unable to parse RSA public key, generating a temp one", err)
		return GenRsaKey(4096)
	}
	pubKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		logger.Error.Println("Unable to parse RSA public key, generating a temp one", err)
		return GenRsaKey(4096)
	}

	privateKey.PublicKey = *pubKey
	return privateKey, nil
}

// GenRsaKey - Generate a RSA KeyPair
func GenRsaKey(size int) (privateKey *rsa.PrivateKey, err error) {
	privKey, err := rsa.GenerateKey(rand.Reader, size)
	return privKey, err
}

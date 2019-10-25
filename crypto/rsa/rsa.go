package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/jafossum/go-auth-server/crypto/base64"
	"github.com/jafossum/go-auth-server/utils/logger"
)

// GetSha1Thumbprint - Get Thumbprint from cert
func GetSha1Thumbprint(key *rsa.PublicKey) string {
	pubbytes := x509.MarshalPKCS1PublicKey(key)
	ans := sha1.Sum(pubbytes)
	return (base64.EncodeToString([]byte(fmt.Sprintf("%x", ans))))
}

// RSA handling inspired by this GIST - Modified to work :)
// https://gist.github.com/jshap70/259a87a7146393aab5819873a193b88c

// ParseRsaKeys - Parse keys and validate, or generate a temporary pair
func ParseRsaKeys(rsaPrivKey, rsaPrivPass, rsaPubKey string) (*rsa.PrivateKey, error) {
	if rsaPrivKey == "" {
		logger.Warning.Println("No RSA Key given, generating temp one")
		return genRsaKey(2048)
	}
	priv, err := ioutil.ReadFile(rsaPrivKey)
	if err != nil {
		logger.Warning.Println("No RSA private key found, generating temp one", nil)
		return genRsaKey(2048)
	}
	privPem, _ := pem.Decode(priv)
	if privPem.Type != "PRIVATE KEY" {
		logger.Warning.Println("RSA private key is of the wrong type: ", privPem.Type)
	}
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPem.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPem.Bytes); err != nil { // note this returns type `interface{}`
			logger.Error.Println("Unable to parse RSA private key, generating a temp one", err)
			return genRsaKey(2048)
		}
	}
	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		logger.Error.Println("Unable to parse RSA private key, generating a temp one", err)
		return genRsaKey(2048)
	}

	pub, err := ioutil.ReadFile(rsaPubKey)
	if err != nil {
		logger.Warning.Println("No RSA public key found, generating temp one", nil)
		return genRsaKey(2048)
	}
	pubPem, _ := pem.Decode(pub)
	if pubPem == nil {
		logger.Error.Println("Use `ssh-keygen -f id_rsa.pub -e -m pem > id_rsa.pem` to generate the pem encoding of your RSA public key",
			fmt.Errorf("RSA public key not in pem format: %s", rsaPubKey))
		return genRsaKey(2048)
	}
	if pubPem.Type != "PUBLIC KEY" {
		logger.Warning.Println("RSA public key is of the wrong type: ", pubPem.Type)
		return genRsaKey(2048)
	}
	if parsedKey, err = x509.ParsePKCS1PublicKey(pubPem.Bytes); err != nil {
		logger.Error.Println("Unable to parse RSA public key, generating a temp one", err)
		return genRsaKey(2048)
	}
	pubKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		logger.Error.Println("Unable to parse RSA public key, generating a temp one", err)
		return genRsaKey(2048)
	}

	privateKey.PublicKey = *pubKey
	return privateKey, nil
}

// genRsaKey - Generate a RSA KeyPair
func genRsaKey(size int) (privateKey *rsa.PrivateKey, err error) {
	privKey, err := rsa.GenerateKey(rand.Reader, size)
	return privKey, err
}

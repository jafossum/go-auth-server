package handlers

import (
	"crypto/rsa"
	"crypto/sha1"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jafossum/go-auth-server/logger"
	"github.com/jafossum/go-auth-server/models"
)

// JwksHandler - JWKS handler
var JwksHandler = &jwksHandler{}

type jwksHandler struct {
	privateKey *rsa.PrivateKey
}

// SetCertificate - Initialize with setting certificates
func (h *jwksHandler) SetCertificate(privateKey *rsa.PrivateKey) {
	h.privateKey = privateKey
}

// Handle - JWKS Endpoint handler
func (h *jwksHandler) Handle(w http.ResponseWriter, r *http.Request) {
	logger.Info.Println("JWKS Endpoint")

	fp := sha1.Sum([]byte(fmt.Sprintf("%v", h.privateKey.PublicKey)))

	key := &models.JSONWebKeys{}
	key.Alg = "RSA256"
	key.Kty = "RSA"
	key.Use = "sig"
	key.X5c = []string{b64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%v", h.privateKey.PublicKey)))}
	key.N = b64.URLEncoding.EncodeToString([]byte(h.privateKey.PublicKey.N.String()))
	key.E = "AQAB"
	key.Kid = b64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%x", fp)))
	key.X5t = b64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%x", fp)))

	fmt.Println(fp)

	keys := &models.Jwks{Keys: []models.JSONWebKeys{*key}}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keys)
}

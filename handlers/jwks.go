package handlers

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"net/http"

	"github.com/jafossum/go-auth-server/models"
	"github.com/jafossum/go-auth-server/utils/base64"
	"github.com/jafossum/go-auth-server/utils/logger"
	rsaa "github.com/jafossum/go-auth-server/utils/rsa"
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

	pub := base64.EncodeToString(x509.MarshalPKCS1PublicKey(&h.privateKey.PublicKey))
	fp := rsaa.GetSha1Thumbprint(&h.privateKey.PublicKey)

	key := &models.JSONWebKeys{}
	key.Alg = "RSA256"
	key.Kty = "RSA"
	key.Use = "sig"
	key.X5c = []string{pub}
	key.N = base64.EncodeToString(h.privateKey.PublicKey.N.Bytes())
	key.E = base64.EncodeUint64ToString(uint64(h.privateKey.E))
	key.Kid = fp
	key.X5t = fp

	keys := &models.Jwks{Keys: []models.JSONWebKeys{*key}}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keys)
}

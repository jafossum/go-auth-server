package handlers

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"

	"github.com/jafossum/go-auth-server/crypto/base64"
	rsaa "github.com/jafossum/go-auth-server/crypto/rsa"
	"github.com/jafossum/go-auth-server/models"
	"github.com/jafossum/go-auth-server/utils/logger"
)

//go:generate mockgen -destination=../mocks/jwks_handler_mock.go -package=mocks github.com/jafossum/go-auth-server/handlers IJwksHandler

// IJwksHandler : JwksHandler Interace
type IJwksHandler interface {
	SetCertificate(privateKey *rsa.PrivateKey)
	Handle(w http.ResponseWriter, r *http.Request)
}

// JwksHandler - JWKS handler
var JwksHandler IJwksHandler = &jwksHandler{}

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
	w.Header().Set("Content-Type", "application/json")
	jwks, err := h.createJwks()
	if err != nil {
		logger.Error.Printf("JWKS unexpected error: %s", err)
		http.Error(w, `{"error": "Server error"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(jwks)
}

func (h *jwksHandler) createJwks() (*models.Jwks, error) {
	pub, err := rsaa.GetPublicKey(&h.privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	fp, err := rsaa.GetSha1Thumbprint(&h.privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	key := &models.JSONWebKeys{}
	key.Alg = "RSA256"
	key.Kty = "RSA"
	key.Use = "sig"
	key.X5c = []string{pub}
	key.N = base64.EncodeToString(h.privateKey.PublicKey.N.Bytes())
	key.E = base64.EncodeUint64ToString(uint64(h.privateKey.E))
	key.Kid = fp
	key.X5t = fp

	return &models.Jwks{Keys: []models.JSONWebKeys{*key}}, nil
}

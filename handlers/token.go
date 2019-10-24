package handlers

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/jafossum/go-auth-server/utils/logger"
	"github.com/jafossum/go-auth-server/models"
)

// TokenHandler - JWKS handler
var TokenHandler = &tokenHandler{}

type tokenHandler struct {
	privateKey *rsa.PrivateKey
}

// SetCertificate - Initialize with setting certificates
func (h *tokenHandler) SetCertificate(privateKey *rsa.PrivateKey) {
	h.privateKey = privateKey
}

// Handle - Tokewn Endpoint handler
func (h *tokenHandler) Handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req = &models.TokenRequest{}
	_ = json.NewDecoder(r.Body).Decode(req)

	if req.GrantType == "client_credentials" {
		j, err := h.generateJWT(req.Audience)
		if err != nil {
			http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		res := getResponse(j)
		json.NewEncoder(w).Encode(res)
		return
	}
	http.Error(w, `{"error": "Unsupported Grant Type"}`, http.StatusUnauthorized)
	return
}

type myClaimsStructure struct {
	*jwt.StandardClaims
	Admin string `json:"admin"`
}

func (h *tokenHandler) generateJWT(audience string) (string, error) {
	// Create the Claims
	claims := myClaimsStructure{
		&jwt.StandardClaims{
			Issuer:    "GolangAuthServer",
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Second * 3600).Unix(),
			Audience:  audience,
		},
		"1",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(h.privateKey)
	if err != nil {
		logger.Error.Printf("Sign token error: %s", err.Error())
		return "", err
	}
	return tokenString, nil
}

func getResponse(token string) *models.TokenResponse {
	return &models.TokenResponse{
		TokenType:   "bearer",
		AccessToken: token,
		ExpiresIn:   3600,
	}
}

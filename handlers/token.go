package handlers

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/jafossum/go-auth-server/config/auth"
	rsaa "github.com/jafossum/go-auth-server/crypto/rsa"
	"github.com/jafossum/go-auth-server/models"
	"github.com/jafossum/go-auth-server/utils/logger"
)

// TokenHandler - JWKS handler
var TokenHandler = &tokenHandler{}

type tokenHandler struct {
	privateKey    *rsa.PrivateKey
	authorization *auth.Authorization
}

// SetCertificate - Initialize with setting certificates
func (h *tokenHandler) SetCertificate(privateKey *rsa.PrivateKey) {
	h.privateKey = privateKey
}

// SetAuthorization - Initialize with authorization data
func (h *tokenHandler) SetAuthorization(authorization *auth.Authorization) {
	h.authorization = authorization
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
	Scope string `json:"scope"`
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
		"read:messages admin",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = rsaa.GetSha1Thumbprint(&h.privateKey.PublicKey)
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

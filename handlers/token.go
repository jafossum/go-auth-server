package handlers

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/jafossum/go-auth-server/crypto/passwd"
	rsaa "github.com/jafossum/go-auth-server/crypto/rsa"
	"github.com/jafossum/go-auth-server/models"
	"github.com/jafossum/go-auth-server/utils/logger"
)

//go:generate mockgen -destination=../mocks/token_handler_mock.go -package=mocks github.com/jafossum/go-auth-server/handlers ITokenHandler

// ITokenHandler : TokenHandler Interace
type ITokenHandler interface {
	SetCertificate(privateKey *rsa.PrivateKey)
	SetAuthorization(authorization *models.Authorization)
	Handle(w http.ResponseWriter, r *http.Request)
}

// TokenHandler - JWKS handler
var TokenHandler ITokenHandler = &tokenHandler{}

type tokenHandler struct {
	privateKey    *rsa.PrivateKey
	authorization *models.Authorization
}

// SetCertificate - Initialize with setting certificates
func (h *tokenHandler) SetCertificate(privateKey *rsa.PrivateKey) {
	h.privateKey = privateKey
}

// SetAuthorization - Initialize with authorization data
func (h *tokenHandler) SetAuthorization(authorization *models.Authorization) {
	h.authorization = authorization
}

// Handle - Tokewn Endpoint handler
func (h *tokenHandler) Handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req = &models.TokenRequest{}
	_ = json.NewDecoder(r.Body).Decode(req)

	if req.GrantType == "client_credentials" {
		res, err := h.handleClientCredentials(req)
		if err != nil {
			logger.Warning.Println(err)
			http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(res)
		return
	}
	logger.Warning.Printf("GrantType: %s not supported", req.GrantType)
	http.Error(w, `{"error": "Unsupported Grant Type"}`, http.StatusUnauthorized)
	return
}

type myClaimsStructure struct {
	*jwt.StandardClaims
	Admin string `json:"admin"`
	Scope string `json:"scope"`
}

func (h *tokenHandler) handleClientCredentials(req *models.TokenRequest) (*models.TokenResponse, error) {
	for _, client := range h.authorization.GetClients() {
		if client.GetClientId() == req.ClientID {
			if err := passwd.ComparePasswords(req.ClientSecret, client.GetClientSecret()); err != nil {
				return nil, err
			}
			j, err := h.generateJWT(req.Audience, client.GetScope(), client.GetIsAdmin())
			if err != nil {
				return nil, err
			}
			res := getResponse(j)
			return res, nil
		}
	}
	return nil, errors.New("No ClientID - ClientSecret found")
}

func (h *tokenHandler) generateJWT(audience, scope string, admin bool) (string, error) {
	// Create the Claims
	claims := myClaimsStructure{
		&jwt.StandardClaims{
			Issuer:    h.authorization.GetIssuer(),
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Second * 3600).Unix(),
			Audience:  audience,
		},
		fmt.Sprintf("%t", admin),
		scope,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tp, err := rsaa.GetSha1Thumbprint(&h.privateKey.PublicKey)
	token.Header["kid"] = tp
	if err != nil {
		logger.Error.Printf("Thumbprint error: %s", err.Error())
		return "", err
	}
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

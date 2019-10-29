package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	rsaa "github.com/jafossum/go-auth-server/crypto/rsa"
	"github.com/jafossum/go-auth-server/models"
	"github.com/jafossum/go-auth-server/utils/logger"
)

// Important to not get nullpointer on logger!
func init() {
	logger.StOutInit()
}

var auth = &models.Authorization{Issuer: "Test-Issuer", Clients: []*models.Client{
	&models.Client{ClientId: "cl1", ClientSecret: "$2a$10$85r4AxaXGAzh7G1nCsm7MOYmDfyORw/IuXu33OLY6rvtLEKkVI03G", IsAdmin: false, Scope: "sc"},
	&models.Client{ClientId: "cl2", ClientSecret: "$2a$10$a/JANxkdgbJtc0i36ZEk.eVxoUaMdvMhr/k4fpjL5kTbAeZJFpeIm", IsAdmin: true, Scope: "sc"},
	&models.Client{ClientId: "cl3", ClientSecret: "$2a$10$0sxSR6FKk8msHgPSBN0Au.sGW3HQxRughWXsAZMq8GAVDcrTfFeLm", IsAdmin: true}}}

func TestTokenHandle(t *testing.T) {
	var testResp = []struct {
		req *models.TokenRequest // request
		err bool                 // expe error
	}{
		{&models.TokenRequest{GrantType: "client_credentials", ClientID: "cl1", ClientSecret: "secret1", Audience: "Aud"}, false},
		{&models.TokenRequest{GrantType: "", ClientID: "cl1", ClientSecret: "secret1", Audience: "Aud"}, true},
		{&models.TokenRequest{GrantType: "client_credentials", ClientID: "cl2", ClientSecret: "secret2", Audience: ""}, false},
		{&models.TokenRequest{GrantType: "", ClientID: "cl2", ClientSecret: "secret2", Audience: ""}, true},
	}

	key, _ := rsaa.ParseRsaKeys("../test-resources/private.pem", "", "../test-resources/public.pem")
	h := tokenHandler{}
	h.SetCertificate(key)
	h.SetAuthorization(auth)

	for _, tc := range testResp {
		t.Run(tc.req.ClientID+tc.req.ClientSecret+tc.req.GrantType, func(t *testing.T) {
			payload, err := json.Marshal(tc.req)
			if err != nil {
				t.Errorf("Got uinexpected error: %v", err)
			}
			req, err := http.NewRequest("POST", "/oauth/token", bytes.NewReader(payload))
			if err != nil {
				t.Errorf("Got uinexpected error: %v", err)
			}

			rr := httptest.NewRecorder()
			// Need to create a router that we can pass the request through so that the vars will be added to the context
			handler := http.HandlerFunc(h.Handle)
			handler.ServeHTTP(rr, req)

			// In this case, our MetricsHandler returns a non-200 response
			// for a route variable it doesn't know about.
			if rr.Code == http.StatusOK && tc.err {
				t.Errorf("handler should have failed on grant_type %s: got %v want %v",
					tc.req.GrantType, rr.Code, http.StatusOK)
			}
			if rr.Code == http.StatusUnauthorized && !tc.err {
				t.Errorf("handler should have failed on grant_type %s: got %v want %v",
					tc.req.GrantType, rr.Code, http.StatusUnauthorized)
			}
		})
	}
}

func TestHandleClientCredentials(t *testing.T) {
	key, _ := rsaa.ParseRsaKeys("../test-resources/private.pem", "", "../test-resources/public.pem")
	h := tokenHandler{}
	h.SetCertificate(key)
	h.SetAuthorization(auth)

	var testResp = []struct {
		req *models.TokenRequest // request
		err bool                 // expe error
	}{
		{&models.TokenRequest{GrantType: "", ClientID: "cl1", ClientSecret: "secret1", Audience: "Aud"}, false},
		{&models.TokenRequest{GrantType: "", ClientID: "cl2", ClientSecret: "secret2", Audience: ""}, false},
		{&models.TokenRequest{GrantType: "", ClientID: "cl3", ClientSecret: "secret3", Audience: ""}, false},
		{&models.TokenRequest{GrantType: "", ClientID: "cl1", ClientSecret: "secret2", Audience: ""}, true},
		{&models.TokenRequest{GrantType: "", ClientID: "cl5", ClientSecret: "", Audience: ""}, true},
	}

	for _, tc := range testResp {
		t.Run(tc.req.ClientID+tc.req.ClientSecret, func(t *testing.T) {
			tc := tc // rebind tc into this lexical scope
			t.Parallel()
			_, err := h.handleClientCredentials(tc.req)
			if err == nil && tc.err {
				t.Error("Not getting expected error")
			}
			if err != nil && !tc.err {
				t.Errorf("Error not expected error; %v", err)
			}
		})
	}
}

func TestGenerateJWT(t *testing.T) {
	key, _ := rsaa.ParseRsaKeys("../test-resources/private.pem", "", "../test-resources/public.pem")
	h := tokenHandler{}
	h.SetCertificate(key)

	var testResp = []struct {
		a   string // audience
		s   string // scope
		adm bool   // admin
		err bool   // expe error
	}{
		{a: "Aud", s: "Scope", adm: false, err: false},
		{a: "A", s: "", adm: false, err: false},
		{a: "Aud", s: "Scope", adm: true, err: false},
	}

	for _, tc := range testResp {
		t.Run(tc.a+tc.s, func(t *testing.T) {
			tc := tc // rebind tc into this lexical scope
			t.Parallel()
			res, err := h.generateJWT(tc.a, tc.s, tc.adm)
			if err == nil && tc.err {
				t.Error("Not getting expected error")
			}
			if err != nil && !tc.err {
				t.Error("Error not expected error")
			}
			if res == "" {
				t.Errorf("generateJWT(%s, %s, %v), Expected: something, Got: %v", tc.a, tc.s, tc.adm, res)
			}
		})
	}
}

func TestGenerateJWTPanicWithNoKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()
	h := tokenHandler{}
	h.generateJWT("Aud", "Scope", false)
	t.Error("Not getting expected panic")
}

func TestGetResponse(t *testing.T) {
	var testResp = []struct {
		token string                // input
		exp   *models.TokenResponse // expected result
	}{
		{"Token1", &models.TokenResponse{TokenType: "bearer", AccessToken: "Token1", ExpiresIn: 3600, RefreshToken: "", Scope: ""}},
		{"t", &models.TokenResponse{TokenType: "bearer", AccessToken: "t", ExpiresIn: 3600, RefreshToken: "", Scope: ""}},
		{"", &models.TokenResponse{TokenType: "bearer", AccessToken: "", ExpiresIn: 3600, RefreshToken: "", Scope: ""}},
	}

	for _, tc := range testResp {
		t.Run(tc.token, func(t *testing.T) {
			tc := tc // rebind tc into this lexical scope
			t.Parallel()
			res := getResponse(tc.token)
			if res.TokenType != tc.exp.TokenType {
				t.Errorf("getResponse(%s), Expected: %v, Got: %v", tc.token, tc.exp, res)
			}
			if res.AccessToken != tc.exp.AccessToken {
				t.Errorf("getResponse(%s), Expected: %v, Got: %v", tc.token, tc.exp, res)
			}
			if res.ExpiresIn != tc.exp.ExpiresIn {
				t.Errorf("getResponse(%s), Expected: %v, Got: %v", tc.token, tc.exp, res)
			}
			if res.RefreshToken != tc.exp.RefreshToken {
				t.Errorf("getResponse(%s), Expected: %v, Got: %v", tc.token, tc.exp, res)
			}
			if res.Scope != tc.exp.Scope {
				t.Errorf("getResponse(%s), Expected: %v, Got: %v", tc.token, tc.exp, res)
			}
		})
	}
}

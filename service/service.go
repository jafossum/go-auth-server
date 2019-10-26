package service

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/gogo/protobuf/jsonpb"
	"github.com/gorilla/mux"
	"github.com/jafossum/go-auth-server/config"
	"github.com/jafossum/go-auth-server/config/auth"
	rsaa "github.com/jafossum/go-auth-server/crypto/rsa"
	"github.com/jafossum/go-auth-server/handlers"
	"github.com/jafossum/go-auth-server/handlers/middleware"
	"github.com/jafossum/go-auth-server/utils/logger"
)

// Service : Service Struct
type Service struct {
	config  *config.ServiceConfig
	forever chan struct{}
}

// NewService : Create a new service
func NewService(config *config.ServiceConfig) *Service {
	return &Service{
		config:  config,
		forever: make(chan struct{}),
	}
}

// Start : Starte Service
func (s *Service) Start() error {
	go s.run()
	return nil
}

// Stop : Stop Service
func (s *Service) Stop() error {
	close(s.forever)
	return nil
}

func (s *Service) run() {
	defer catchPanic()
	logger.Info.Println("Auth Service Starting")

	// Read Authorization data
	authData, err := s.parseAuthorizationData()
	if err != nil {
		logger.Error.Fatalln(err)
	}

	// TLS options. Can be used without, but only for testing!!
	t := &tls.Config{}
	s.setTLSConfig(t)

	// Load ort generate RSA keys
	privateKey, err := s.getRSAKeys()
	if err != nil {
		logger.Error.Fatalln("Load or Generation of RSA key failed")
	}

	// Handlers
	jwks := handlers.JwksHandler
	jwks.SetCertificate(privateKey)

	token := handlers.TokenHandler
	token.SetCertificate(privateKey)
	token.SetAuthorization(authData)

	r := mux.NewRouter()
	r.HandleFunc("/.well-known/jwks.json", jwks.Handle).Methods("GET")
	r.HandleFunc("/oauth/token", token.Handle).Methods("POST")
	r.Use(middleware.LoggingMiddleware)

	srv := &http.Server{
		Handler: r,
		Addr:    fmt.Sprintf(":%s", s.config.Port),
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		TLSConfig:    t,
	}

	// Run our server in a goroutine so that it doesn't block.
	go s.serve(srv)

	// Block untill Close gets called
	<-s.forever

	// Shutdown server before exit
	ctx := context.Background()
	srv.Shutdown(ctx)
}

// parseAuthorizationData - Read and parse Authorization data from file
func (s *Service) parseAuthorizationData() (*auth.Authorization, error) {
	js, err := ioutil.ReadFile(s.config.UserConf)
	if err != nil {
		return nil, fmt.Errorf("Authorization config file: %s could not be loaded", s.config.UserConf)
	}
	a := &auth.Authorization{}
	jsonpb.UnmarshalString(string(js), a)

	return a, nil
}

// setTLSConfig - Set TLS confog
func (s *Service) setTLSConfig(t *tls.Config) {
	// TLS options. Can be used without, but only for testing!!
	if s.config.TLSConf.Cert != "" && s.config.TLSConf.Key != "" {
		// TLS Certs
		cer, err := tls.LoadX509KeyPair(
			s.config.TLSConf.Cert,
			s.config.TLSConf.Key)
		if err != nil {
			logger.Error.Fatal("Load of TLS certs failed")
		}
		t.Certificates = []tls.Certificate{cer}
	}
}

// getRSAKeys - Read or Create and parse RSA keys
func (s *Service) getRSAKeys() (*rsa.PrivateKey, error) {
	return rsaa.ParseRsaKeys(
		s.config.RSAConf.Private,
		s.config.RSAConf.Pass,
		s.config.RSAConf.Public)
}

// serve - Start the HTTP Server
func (s *Service) serve(srv *http.Server) {
	if len(srv.TLSConfig.Certificates) > 0 {
		logger.Info.Println("Auth Service running with TLS enabled")
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			logger.Error.Println(err)
		}
	} else {
		logger.Warning.Println("Auth Service running WITHOUT TLS!")
		if err := srv.ListenAndServe(); err != nil {
			logger.Error.Println(err)
		}
	}
}

// catchPanic : Catch panic() calls and log them before exiting.
func catchPanic() {
	if err := recover(); err != nil {
		logger.Error.Printf("panic: %v\n\n%s", err, debug.Stack())
		logger.Error.Println("Sendin SIGINT for clean shutdown")
		p, _ := os.FindProcess(syscall.Getpid())
		p.Signal(syscall.SIGINT)
	}
}

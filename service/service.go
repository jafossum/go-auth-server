package service

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/jafossum/go-auth-server/config"
	"github.com/jafossum/go-auth-server/handlers"
	"github.com/jafossum/go-auth-server/handlers/middleware"
	"github.com/jafossum/go-auth-server/utils/logger"
	"github.com/jafossum/go-auth-server/crypto/rsa"
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
	logger.Info.Println("Auth Service running")

	// Load ort generate RSA keys
	privateKey, err := rsa.ParseRsaKeys(s.config.RsaPrivate, s.config.RsaPass, s.config.RsaPublic)
	if err != nil {
		logger.Error.Fatal("Load or Generation of RSA key failed")
	}

	// Handlers
	jwks := handlers.JwksHandler
	jwks.SetCertificate(privateKey)

	token := handlers.TokenHandler
	token.SetCertificate(privateKey)

	r := mux.NewRouter()
	r.HandleFunc("/.well-known/jwks.json", jwks.Handle).Methods("GET")
	r.HandleFunc("/auth/token", token.Handle).Methods("POST")
	r.Use(middleware.LoggingMiddleware)

	srv := &http.Server{
		Handler: r,
		Addr:    fmt.Sprintf("127.0.0.1:%s", s.config.Port),
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	// Run our server in a goroutine so that it doesn't block.
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	// Block untill Close gets called
	<-s.forever

	// Shutdown server before exit
	ctx := context.Background()
	srv.Shutdown(ctx)
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

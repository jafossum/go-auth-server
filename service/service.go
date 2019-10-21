package service

import (
	"os"
	"runtime/debug"
	"syscall"

	"github.com/jafossum/go-auth-server/config"
	"github.com/jafossum/go-auth-server/logger"
	"github.com/jafossum/go-auth-server/rsa"
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
	privateKey, err := rsa.ParseRsaKeys(s.config.RsaPrivate, s.config.RsaPublic, s.config.RsaPass)
	if err != nil {
		logger.Error.Fatal("Load or Generation of RSA key failed")
	}

	logger.Info.Println("Private Key: ", privateKey)
	logger.Trace.Println("Public key: ", privateKey.PublicKey)

	<-s.forever
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

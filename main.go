package main

import (
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jafossum/go-auth-server/models"
	"github.com/jafossum/go-auth-server/service"
	"github.com/jafossum/go-auth-server/utils/logger"
	"github.com/namsral/flag"
)

func main() {

	c := parseConfig()
	f, err := setLogFile(c.LogFile)
	if err != nil {
		logger.Error.Fatalln("Failed to open log file", c.LogFile, ":", err)
		os.Exit(1)
	}
	defer f.Close()

	// Initialize and start runner service
	s := service.NewService(c)
	s.Start()

	// Run forever
	blockOnSignal(s)
}

// parseConfig : Parse config from file, env or commandline
func parseConfig() (c *models.ServiceConfig) {
	c = &models.ServiceConfig{}
	r := &models.RSAConfig{}
	t := &models.TLSConfig{}
	flag.String(flag.DefaultConfigFlagname, "", "path to config file")
	flag.StringVar(&c.LogFile, "log_logfile", "./logs/out.log", "Directory to write logs")
	flag.StringVar(&c.Port, "port", "9065", "Server port")
	flag.StringVar(&r.Private, "rsa_private", "", "Path to RSA Private Key")
	flag.StringVar(&r.Public, "rsa_public", "", "Path to RSA Public Key")
	flag.StringVar(&r.Pass, "rsa_pass", "", "RSA PrivateKey Password")
	flag.StringVar(&t.Key, "tls_key", "", "Path to TLS Key")
	flag.StringVar(&t.Cert, "tls_cert", "", "Path to TLS Certificate")
	flag.StringVar(&c.UserConf, "user_conf", "./config/auth_conf.json", "Path to User Configuration file. Protobuf formatted JSON.")
	flag.Parse()
	c.RSAConf = r
	c.TLSConf = t
	return
}

// setLogFile : Initalises Logger
func setLogFile(logfile string) (*os.File, error) {
	logDir := filepath.Dir(logfile)
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		// logfile path deos not exist. Creating path
		if err := os.MkdirAll(logDir, os.ModePerm); err != nil {
			return nil, err
		}
	}
	file, err := os.OpenFile(logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}
	multi := io.MultiWriter(file, os.Stdout)
	mulErr := io.MultiWriter(file, os.Stderr)
	logger.Init(os.Stdout, multi, multi, mulErr)

	return file, nil
}

// Cmd - Struct for cmd channel
type Cmd struct {
	Closed chan struct{}
}

// Close - Shutdowen routine
func (c *Cmd) Close() {
	logger.Info.Println("closing program...")
	// wait for program to clean up nicely
	time.Sleep(2 * time.Second)
	logger.Info.Println("closed program")
	close(c.Closed)
}

// blockOnSignal : Blocks until signal and atempts clean shutdown
func blockOnSignal(s *service.Service) {
	cmd := Cmd{Closed: make(chan struct{})}
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	logger.Trace.Println("Listening for signals")

	// Block until one of the signals above is received
	<-signalCh
	logger.Info.Println("Signal received, initializing clean shutdown...")
	go cmd.Close()

	// Stopping service
	go s.Stop()

	// Block again until another signal is received, a shutdown timeout elapses,
	// or the Command is gracefully closed
	logger.Info.Println("Waiting for clean shutdown...")
	select {
	case <-signalCh:
		logger.Warning.Println("second signal received, initializing hard shutdown")
	case <-time.After(time.Second * 5):
		logger.Warning.Println("time limit reached, initializing hard shutdown")
	case <-cmd.Closed:
		logger.Info.Println("server shutdown completed")
	}
}

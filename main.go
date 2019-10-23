package main

import (
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jafossum/go-auth-server/config"
	"github.com/jafossum/go-auth-server/logger"
	"github.com/jafossum/go-auth-server/service"
	"github.com/namsral/flag"
)

func main() {

	c := parseConfig()
	f := setLogFile(c.LogFile)
	defer f.Close()

	// Initialize and start runner service
	s := service.NewService(&c)
	s.Start()

	// Run forever
	blockOnSignal(s)
}

// parseConfig : Parse config from file, env or commandline
func parseConfig() (c config.ServiceConfig) {
	c = config.ServiceConfig{}
	flag.StringVar(&c.LogFile, "log_logfile", "./logs/out.log", "Directory to write logs")
	flag.StringVar(&c.Port, "port", "9065", "Server port")
	flag.StringVar(&c.RsaPrivate, "rsa_private", "", "Path to RSA Private Key")
	flag.StringVar(&c.RsaPublic, "rsa_public", "", "Path to RSA Public Key")
	flag.StringVar(&c.RsaPass, "rsa_pass", "", "RSA PrivateKey Password")
	flag.Parse()
	return
}

// setLogFile : Initalises Logger
func setLogFile(logfile string) *os.File {
	file, err := os.OpenFile(logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		logger.Error.Fatalln("Failed to open log file", file, ":", err)
	}
	multi := io.MultiWriter(file, os.Stdout)
	mulErr := io.MultiWriter(file, os.Stderr)
	logger.Init(os.Stdout, multi, multi, mulErr)

	return file
}

// Cmd - Struct for cmd channel
type Cmd struct {
	Closed chan struct{}
}

// Close - Shutdowen routine
func (c *Cmd) Close() {
	log.Println("closing program...")
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
	log.Println("Waiting for clean shutdown...")
	select {
	case <-signalCh:
		logger.Warning.Println("second signal received, initializing hard shutdown")
	case <-time.After(time.Second * 5):
		logger.Warning.Println("time limit reached, initializing hard shutdown")
	case <-cmd.Closed:
		logger.Info.Println("server shutdown completed")
	}
}

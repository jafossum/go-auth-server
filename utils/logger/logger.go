package logger

import (
	"io"
	"io/ioutil"
	"log"
	"os"
)

var (
	// Trace : Trace logger
	Trace *log.Logger
	// Info : Info logger
	Info *log.Logger
	// Warning : Warning logger
	Warning *log.Logger
	// Error : Error logger
	Error *log.Logger
)

// Init : Initialize logger with io.Writer
func Init(
	traceHandle io.Writer,
	infoHandle io.Writer,
	warningHandle io.Writer,
	errorHandle io.Writer) {

	Trace = log.New(traceHandle,
		"TRACE: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Info = log.New(infoHandle,
		"INFO: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Warning = log.New(warningHandle,
		"WARNING: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Error = log.New(errorHandle,
		"ERROR: ",
		log.Ldate|log.Ltime|log.Lshortfile)
}

// TestInit : Must be called duriong testing to avoid nullpointer
func TestInit() {
	Trace = log.New(ioutil.Discard, "", log.Ldate)
	Info = log.New(ioutil.Discard, "", log.Ldate)
	Warning = log.New(ioutil.Discard, "", log.Ldate)
	Error = log.New(ioutil.Discard, "", log.Ldate)
}

// StOutInit : Set all loggers to StOut
func StOutInit() {
	Trace = log.New(os.Stdout, "", log.Ldate)
	Info = log.New(os.Stdout, "", log.Ldate)
	Warning = log.New(os.Stdout, "", log.Ldate)
	Error = log.New(os.Stdout, "", log.Ldate)
}

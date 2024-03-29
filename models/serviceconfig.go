package models

// ServiceConfig : Config for service
type ServiceConfig struct {
	Port     string
	LogFile  string
	RSAConf  *RSAConfig
	TLSConf  *TLSConfig
	UserConf string
}

// RSAConfig - RSA filespaths for signing config
type RSAConfig struct {
	Private string
	Public  string
	Pass    string
}

// TLSConfig -  TLS filepaths
type TLSConfig struct {
	Key  string
	Cert string
}

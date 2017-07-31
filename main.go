package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/Sirupsen/logrus"

	"github.com/docker/engine-api/client"
	"github.com/zanecloud/tunneld/tunnel/audit/zaneaudit"
	"github.com/zanecloud/tunneld/tunnel/ssh"
)

const (
	VERSION         string = "v1.0"
	REQUEST_TIMEOUT        = 30 * time.Second
)

var (
	PrintVersion bool
	ListenAddr   string
	//DockerAddr string

	// tls
	TLSVerify bool
	TLSCacert string
	TLSCert   string
	TLSKey    string

	IsNoSshAuth bool
	IsDebug     bool
)

func init() {
	log.SetPrefix(os.Args[0] + " | ")

	flag.BoolVar(&PrintVersion, "v", false, "Show Tunneld Version")
	flag.StringVar(&ListenAddr, "l", "0.0.0.0:2022", "Tunneld Listen Address")

	//flag.StringVar(&DockerAddr, "d", "localhost:2376", "Swarm or Docker Listen Address")
	//flag.BoolVar(&TLSVerify, "tlsverify", false, "Use TLS and verify the remote")
	//flag.StringVar(&TLSCacert, "tlscacert", "~/.docker/ca.pem", "Trust certs signed only by this CA")
	//flag.StringVar(&TLSCert, "tlscert", "~/.docker/cert.pem", "Path to TLS certificate file")
	//flag.StringVar(&TLSKey, "tlskey", "~/.docker/key.pem", "Path to TLS key file")

	flag.BoolVar(&IsNoSshAuth, "noauth", false, "No Ssh Auth")
	flag.BoolVar(&IsDebug, "debug", false, "Debug Log Level")
}

func exit() {
	if err := recover(); err != nil {
		if _, ok := err.(runtime.Error); ok {
			log.Println(err)
		}
		os.Exit(1)
	}
	os.Exit(0)
}

// Load the TLS certificates/keys and, if verify is true, the CA.
func loadTLSConfig(ca, cert, key string, verify bool) (*tls.Config, error) {
	var config *tls.Config

	if verify {
		config = &tls.Config{
			MinVersion: tls.VersionTLS10,
		}
		c, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, fmt.Errorf("Couldn't load X509 key pair (%s, %s): %s. Key encrypted?",
				cert, key, err)
		}
		config.Certificates = []tls.Certificate{c}

		certPool := x509.NewCertPool()
		file, err := ioutil.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("Couldn't read CA certificate: %s", err)
		}
		certPool.AppendCertsFromPEM(file)
		config.RootCAs = certPool
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = certPool
		//config.InsecureSkipVerify = true
	} else {
		// If --tlsverify is not supplied, disable CA validation.
		config = nil
	}

	return config, nil
}

func main() {
	flag.Parse()
	defer exit()

	if IsDebug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if PrintVersion {
		fmt.Printf("Tunneld: %s\n", VERSION)
		return
	}

	//logrus.Infoln("Connect swarm/docker at", DockerAddr)
	//tlsConfig, err := loadTLSConfig(TLSCacert, TLSCert, TLSKey, TLSVerify)
	//c, err := client.NewHTTPClientTimeout(DockerAddr, tlsConfig, REQUEST_TIMEOUT)
	c, err := client.NewEnvClient()
	if err != nil {
		logrus.Fatal("Error occurs when create docker client: ", err)
	}

	// new audit client
	auditClient, err := zaneaudit.NewEnvClient()
	if err != nil {
		logrus.Warning("Audit is disabled: ", err)
	}

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", ListenAddr)
	if err != nil {
		logrus.Fatal("failed to listen for connection: ", err)
	}

	logrus.Printf("Tunneld Listening on %s", ListenAddr)
	for {
		// keep listen new connections
		nConn, err := listener.Accept()
		if err != nil {
			logrus.Errorln("failed to accept incoming connection: ", err)
			continue
		}

		err = ssh.HandleSSHConnection(nConn, c, auditClient, IsNoSshAuth)
		if err != nil {
			logrus.Errorln("error occurs in ssh listen server: ", err)
			continue
		}
	}

}

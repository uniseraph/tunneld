package zaneaudit

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/docker/engine-api/client/transport"
	"github.com/zanecloud/tunneld/tunnel/audit"
)

const ZANE_API_VERSION = "1.0"
const REQUEST_TIMEOUT = 15 * time.Second

type ZaneAuditClient struct {
	// proto holds the client protocol i.e. unix.
	proto string
	// addr holds the client address.
	addr string
	// basePath holds the path to prepend to the requests.
	basePath string
	// transport is the interface to sends request with, it implements transport.Client.
	transport transport.Client
	// version of the server to talk to.
	version string
	// custom http headers configured by users.
	customHTTPHeaders map[string]string
	// isSync let request use sync or async
	IsSync bool
}

type tcpFunc func(*net.TCPConn, time.Duration) error

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

func newHTTPClient(u *url.URL, tlsConfig *tls.Config, timeout time.Duration, setUserTimeout tcpFunc) *http.Client {
	if tlsConfig == nil {
		// let the api client configure the default transport.
		return nil
	}

	httpTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	switch u.Scheme {
	default:
		httpTransport.Dial = func(proto, addr string) (net.Conn, error) {
			conn, err := net.DialTimeout(proto, addr, timeout)
			if tcpConn, ok := conn.(*net.TCPConn); ok && setUserTimeout != nil {
				// Sender can break TCP connection if the remote side doesn't
				// acknowledge packets within timeout
				setUserTimeout(tcpConn, timeout)
			}
			return conn, err
		}
	case "unix":
		socketPath := u.Path
		unixDial := func(proto, addr string) (net.Conn, error) {
			return net.DialTimeout("unix", socketPath, timeout)
		}
		httpTransport.Dial = unixDial
		// Override the main URL object so the HTTP lib won't complain
		u.Scheme = "http"
		u.Host = "unix.sock"
		u.Path = ""
	}
	return &http.Client{Transport: httpTransport}
}

func NewEnvClient() (audit.AuditClient, error) {
	var tlsConfig *tls.Config
	var err error

	if zaneCertPath := os.Getenv("ZANE_AUDIT_CERT_PATH"); zaneCertPath != "" {
		tlsConfig, err = loadTLSConfig(filepath.Join(zaneCertPath, "ca.pem"), filepath.Join(zaneCertPath, "cert.pem"),
			filepath.Join(zaneCertPath, "key.pem"), os.Getenv("ZANE_AUDIT_TLS_VERIFY") == "")
		if err != nil {
			return nil, err
		}
	}

	host := os.Getenv("ZANE_AUDIT_HOST")
	if host == "" {
		return nil, errors.New("No audit host input")
	}
	apiVersion := os.Getenv("ZANE_API_VERSION")
	if apiVersion == "" {
		apiVersion = ZANE_API_VERSION
	}
	isSyncStr := os.Getenv("ZANE_AUDIT_IS_SYNC")
	var isSync bool
	if isSyncStr != "" {
		isSync = true
	}

	return NewClientTimeout(host, apiVersion, tlsConfig, REQUEST_TIMEOUT, isSync)
}

func NewClientTimeout(host string, version string, tlsConfig *tls.Config, timeout time.Duration, isSync bool) (*ZaneAuditClient, error) {
	u, err := url.Parse(host)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Scheme == "tcp" {
		if tlsConfig == nil {
			u.Scheme = "http"
		} else {
			u.Scheme = "https"
		}
	}
	httpClient := newHTTPClient(u, tlsConfig, timeout, setTCPUserTimeout)
	customHeaders := map[string]string{}

	proto, addr, basePath, err := ParseHost(host)
	if err != nil {
		return nil, err
	}

	transport, err := transport.NewTransportWithHTTP(proto, addr, httpClient)
	if err != nil {
		return nil, err
	}

	return &ZaneAuditClient{
		proto:             proto,
		addr:              addr,
		basePath:          basePath,
		transport:         transport,
		version:           version,
		customHTTPHeaders: customHeaders,
		IsSync:            isSync,
	}, nil
}

// setTCPUserTimeout sets TCP_USER_TIMEOUT according to RFC5842
func setTCPUserTimeout(conn *net.TCPConn, uto time.Duration) error {
	f, err := conn.File()
	if err != nil {
		return err
	}
	defer f.Close()

	msecs := int(uto.Nanoseconds() / 1e6)
	// TCP_USER_TIMEOUT is a relatively new feature to detect dead peer from sender side.
	// Linux supports it since kernel 2.6.37. It's among Golang experimental under
	// golang.org/x/sys/unix but it doesn't support all Linux platforms yet.
	// we explicitly define it here until it becomes official in golang.
	// TODO: replace it with proper package when TCP_USER_TIMEOUT is supported in golang.
	const tcpUserTimeout = 0x12
	return os.NewSyscallError("setsockopt", syscall.SetsockoptInt(int(f.Fd()), syscall.IPPROTO_TCP, tcpUserTimeout, msecs))
}

// ParseHost verifies that the given host strings is valid.
func ParseHost(host string) (string, string, string, error) {
	protoAddrParts := strings.SplitN(host, "://", 2)
	if len(protoAddrParts) == 1 {
		return "", "", "", fmt.Errorf("unable to parse docker host `%s`", host)
	}

	var basePath string
	proto, addr := protoAddrParts[0], protoAddrParts[1]
	if proto == "tcp" {
		parsed, err := url.Parse("tcp://" + addr)
		if err != nil {
			return "", "", "", err
		}
		addr = parsed.Host
		basePath = parsed.Path
	}
	return proto, addr, basePath, nil
}

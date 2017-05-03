package client

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"os"
	"syscall"
	"time"

	"github.com/docker/engine-api/client"
)

const SWARM_VERSION = "1.23"

type HTTPClient struct {
	Version string
	Scheme string
	Host string
	*client.Client
}

type tcpFunc func(*net.TCPConn, time.Duration) error

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

func NewHTTPClientTimeout(host string, tlsConfig *tls.Config, timeout time.Duration) (*HTTPClient, error) {
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
	customHeaders["User-Agent"] = "Docker-Client/library-import (linux)"

	client, err := client.NewClient("tcp://"+host, SWARM_VERSION, httpClient, customHeaders)
	if err != nil {
		return nil, err
	}

	return &HTTPClient {
		Version: SWARM_VERSION,
		Scheme: u.Scheme,
		Host: host,
		Client: client,
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

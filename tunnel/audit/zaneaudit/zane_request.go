package zaneaudit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/docker/engine-api/client/transport/cancellable"
)

// serverResponse is a wrapper for http API responses.
type serverResponse struct {
	body       io.ReadCloser
	header     http.Header
	statusCode int
}

func (z *ZaneAuditClient) sendClientRequest(ctx context.Context, method, path string, body io.Reader,
	headers map[string][]string) (*serverResponse, error) {
	serverResp := &serverResponse{
		body:       nil,
		statusCode: -1,
	}

	expectedPayload := (method == "POST" || method == "PUT")
	if expectedPayload && body == nil {
		body = bytes.NewReader([]byte{})
	}

	req, err := http.NewRequest(method, path, body)
	req.URL.Host = z.addr
	req.URL.Scheme = z.transport.Scheme()
	if headers != nil {
		for k, v := range headers {
			req.Header[k] = v
		}
	}

	if expectedPayload && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "text/plain")
	}

	resp, err := cancellable.Do(ctx, z.transport, req)
	if resp != nil {
		serverResp.statusCode = resp.StatusCode
	}

	if err != nil {
		if isTimeout(err) || strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "dial unix") {
			logrus.Errorf("Cannot connect to the zane apiserver. Is the zane apiserver running on this host?")
			return serverResp, errors.New("内部错误")
		}

		if !z.transport.Secure() && strings.Contains(err.Error(), "malformed HTTP response") {
			logrus.Errorf("%v.\n* Are you trying to connect to a TLS-enabled daemon without TLS?", err)
			return serverResp, errors.New("内部错误")
		}
		if z.transport.Secure() && strings.Contains(err.Error(), "remote error: bad certificate") {
			logrus.Errorf("The server probably has client authentication (--tlsverify) enabled. Please check your TLS client certification settings: %v", err)
			return serverResp, errors.New("内部错误")
		}

		logrus.Errorf("An error occurred trying to connect: %v", err)
		return serverResp, errors.New("内部错误")
	}

	if serverResp.statusCode < 200 || serverResp.statusCode >= 400 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return serverResp, err
		}
		if len(body) == 0 {
			logrus.Errorf("Error: request returned %s for request path %s, with 0 body", http.StatusText(serverResp.statusCode), req.URL)
			return serverResp, errors.New("内部错误")
		}
		return serverResp, fmt.Errorf("%s", body)
	}

	serverResp.body = resp.Body
	serverResp.header = resp.Header
	return serverResp, nil
}

func ensureReaderClosed(response *serverResponse) {
	if response != nil && response.body != nil {
		response.body.Close()
	}
}

func isTimeout(err error) bool {
	type timeout interface {
		Timeout() bool
	}
	e := err
	switch urlErr := err.(type) {
	case *url.Error:
		e = urlErr.Err
	}
	t, ok := e.(timeout)
	return ok && t.Timeout()
}

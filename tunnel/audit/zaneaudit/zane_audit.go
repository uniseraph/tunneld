package zaneaudit

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Sirupsen/logrus"
	"github.com/zanecloud/tunneld/tunnel/audit"
	"io/ioutil"
	"strings"
)

type Sender interface {
	// Do sends request to a remote endpoint.
	Do(*http.Request) (*http.Response, error)
}

type TransportClient interface {
	Sender
	// Secure tells whether the connection is secure or not.
	Secure() bool
	// Scheme returns the connection protocol the client uses.
	Scheme() string
	// TLSConfig returns any TLS configuration the client uses.
	TLSConfig() *tls.Config
}

/*
	/api/audit/login
*/
func (z *ZaneAuditClient) AuditLogin(auditRequest *audit.AuditLoginRequest) (*audit.AuditLoginResponse, error) {
	reqBody, err := json.Marshal(auditRequest)
	if err != nil {
		logrus.Errorf("AuditLogin: json marshal token: %s, user: %s failed: %v", auditRequest.Token, auditRequest.User, err)
		return nil, errors.New("内部错误")
	}

	resp, err := z.sendClientRequest(context.Background(), "POST", "/api/audit/login", bytes.NewReader(reqBody), nil)
	if err != nil {
		logrus.Errorf("AuditLogin: sendClientRequest with %s, %s, fail, error: %v", auditRequest.Token, auditRequest.User, err)
		return nil, err
	}

	msg, err := ioutil.ReadAll(resp.body)
	if err != nil {
		logrus.Errorf("AuditLogin: ioutil.ReadAll token: %s, user: %s failed: %v", auditRequest.Token, auditRequest.User, err)
		return nil, errors.New("内部错误")
	}
	respJson := strings.TrimSpace(string(msg))

	var respBody audit.AuditLoginResponse
	err = json.Unmarshal([]byte(respJson), &respBody)
	if err != nil {
		logrus.Errorf("AuditLogin: json unmarshal token: %s, user: %s failed: %v", auditRequest.Token, auditRequest.User, err)
		return nil, errors.New("内部错误")
	}
	ensureReaderClosed(resp)
	return &respBody, err
}

/*
	/api/audit/log
*/
func (z *ZaneAuditClient) AuditLog(auditRequest *audit.AuditLogRequest) (*audit.AuditLogResponse, error) {
	reqBody, err := json.Marshal(auditRequest)
	if err != nil {
		logrus.Errorf("AuditLog: json marshal token: %s, user: %s, command: %s, failed: %v",
			auditRequest.Token, auditRequest.User, auditRequest.Command, err)
		return nil, errors.New("内部错误")
	}

	resp, err := z.sendClientRequest(context.Background(), "POST", "/api/audit/log", bytes.NewReader(reqBody), nil)
	if err != nil {
		logrus.Errorf("AuditLog: sendClientRequest with %s, %s, fail, error: %v", auditRequest.Token, auditRequest.User,
			auditRequest.Command, err)
		return nil, err
	}

	msg, err := ioutil.ReadAll(resp.body)
	if err != nil {
		logrus.Errorf("AuditLog: ioutil.ReadAll token: %s, user: %s, command: %s, failed: %v", auditRequest.Token, auditRequest.User,
			auditRequest.Command, err)
		return nil, errors.New("内部错误")
	}
	respJson := strings.TrimSpace(string(msg))

	var respBody audit.AuditLogResponse
	err = json.Unmarshal([]byte(respJson), &respBody)
	if err != nil {
		logrus.Errorf("AuditLog: json unmarshal token: %s, user: %s, command %s, failed: %v",
			auditRequest.Token, auditRequest.User, auditRequest.Command, err)
		return nil, errors.New("内部错误")
	}
	ensureReaderClosed(resp)
	return &respBody, err

}

/*
	/audit/update
*/
func (z *ZaneAuditClient) AuditUpdate(auditRequest *audit.AuditLogRequest) (*audit.AuditLogResponse, error) {
	// not implement
	return nil, nil
}

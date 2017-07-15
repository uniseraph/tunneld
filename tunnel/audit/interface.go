package audit

type AuditClient interface {
	AuditLogin(auditRequest *AuditLoginRequest) (*AuditLoginResponse, error)
	AuditLog(auditRequest *AuditLogRequest) (*AuditLogResponse, error)
	AuditUpdate(auditRequest *AuditLogRequest) (*AuditLogResponse, error)
}

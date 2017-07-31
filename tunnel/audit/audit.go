package audit

type AuditInfo struct {
	AuditClient AuditClient
	Token       string
	User        string
	UpdateId    string
}

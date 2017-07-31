package audit

type AuditLoginRequest struct {
	Token     string `json:"Token"`
	User      string `json:"IP"`
	Timestamp string `json:"Timestamp"`
}

type AuditLoginResponse struct {
	Result    string `json:"Result"`
	Status    int    `json:"Status"`
	Container string `json:"Container"`
}

type AuditLogRequest struct {
	Token     string `json:"Token"`
	User      string `json:"IP"`
	Command   string `json:"Command"`
	Output    string `json:"Output"`
	UpdateId  string `json:"UpdateId"`
	Timestamp string `json:"Timestamp"`
}

type AuditLogResponse struct {
	Result   string `json:"Result"`
	UpdateId string `json:"UpdateId"`
}

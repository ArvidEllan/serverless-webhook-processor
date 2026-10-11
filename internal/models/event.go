package models

import "time"

// WebhookEvent represents an incoming webhook payload after validation.
type WebhookEvent struct {
	EventID   string            `json:"event_id" dynamodbav:"PK"`
	TenantID  string            `json:"tenant_id" dynamodbav:"SK"`
	EventType string            `json:"event_type" dynamodbav:"event_type"`
	Payload   string            `json:"payload" dynamodbav:"payload"` // KMS-encrypted
	Source    string            `json:"source" dynamodbav:"source"`
	Status    EventStatus       `json:"status" dynamodbav:"status"`
	Metadata  map[string]string `json:"metadata,omitempty" dynamodbav:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at" dynamodbav:"created_at"`
	ExpiresAt int64             `json:"expires_at" dynamodbav:"expires_at"` // DynamoDB TTL
}

type EventStatus string

const (
	StatusReceived   EventStatus = "RECEIVED"
	StatusProcessing EventStatus = "PROCESSING"
	StatusProcessed  EventStatus = "PROCESSED"
	StatusFailed     EventStatus = "FAILED"
)

// WebhookResponse is the API Gateway response body.
type WebhookResponse struct {
	EventID string `json:"event_id"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// RateLimitEntry tracks per-tenant request counts in DynamoDB.
type RateLimitEntry struct {
	TenantID     string `dynamodbav:"PK"`
	WindowKey    string `dynamodbav:"SK"` // e.g. "RATELIMIT#2024-10-31T19:00"
	RequestCount int    `dynamodbav:"request_count"`
	TTL          int64  `dynamodbav:"expires_at"`
}

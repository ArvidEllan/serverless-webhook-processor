package middleware

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	MaxPayloadSize = 256 * 1024 // 256KB max payload
	MaxFieldLength = 1024       // Max length for individual string fields
)

var (
	ErrPayloadTooLarge = errors.New("payload exceeds maximum size")
	ErrEmptyBody       = errors.New("request body is empty")
	ErrInvalidJSON     = errors.New("request body is not valid JSON")
	ErrMissingField    = errors.New("required field missing")
	ErrInvalidField    = errors.New("field validation failed")
)

// ValidatedPayload is the result of validation — a known-safe structure.
type ValidatedPayload struct {
	EventType string            `json:"event_type"`
	TenantID  string            `json:"tenant_id"`
	Source    string            `json:"source"`
	Data      json.RawMessage   `json:"data"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// ValidateWebhookPayload performs defense-in-depth validation:
//  1. Size check (before parsing — prevents JSON bomb DoS)
//  2. JSON structure validation
//  3. Required field presence
//  4. Field length limits
//  5. Content sanitization
func ValidateWebhookPayload(body string) (*ValidatedPayload, error) {
	// 1. Size gate — reject before any parsing
	if len(body) == 0 {
		return nil, ErrEmptyBody
	}
	if len(body) > MaxPayloadSize {
		return nil, fmt.Errorf("%w: %d bytes (max %d)", ErrPayloadTooLarge, len(body), MaxPayloadSize)
	}

	// 2. Parse JSON
	var payload ValidatedPayload
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}

	// 3. Required fields
	if payload.EventType == "" {
		return nil, fmt.Errorf("%w: event_type", ErrMissingField)
	}
	if payload.TenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id", ErrMissingField)
	}
	if payload.Data == nil || len(payload.Data) == 0 {
		return nil, fmt.Errorf("%w: data", ErrMissingField)
	}

	// 4. Field length limits
	if len(payload.EventType) > MaxFieldLength {
		return nil, fmt.Errorf("%w: event_type exceeds max length", ErrInvalidField)
	}
	if len(payload.TenantID) > MaxFieldLength {
		return nil, fmt.Errorf("%w: tenant_id exceeds max length", ErrInvalidField)
	}

	// 5. Allowed event types (whitelist approach)
	if !isAllowedEventType(payload.EventType) {
		return nil, fmt.Errorf("%w: unknown event_type %q", ErrInvalidField, payload.EventType)
	}

	// 6. Sanitize tenant ID (alphanumeric + hyphens + underscores only)
	if !isValidTenantID(payload.TenantID) {
		return nil, fmt.Errorf("%w: tenant_id contains invalid characters", ErrInvalidField)
	}

	return &payload, nil
}

// Whitelist of allowed event types.
func isAllowedEventType(eventType string) bool {
	allowed := map[string]bool{
		"payment.completed":  true,
		"payment.failed":     true,
		"payment.refunded":   true,
		"transfer.initiated": true,
		"transfer.completed": true,
		"account.created":    true,
		"account.updated":    true,
		"webhook.test":       true,
	}
	return allowed[eventType]
}

// Validate tenant ID format: alphanumeric, hyphens, underscores.
func isValidTenantID(id string) bool {
	if len(id) < 3 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	// Prevent path traversal attempts
	if strings.Contains(id, "..") || strings.Contains(id, "__") {
		return false
	}
	return true
}

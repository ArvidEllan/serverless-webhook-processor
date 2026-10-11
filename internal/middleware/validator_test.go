package middleware

import (
	"strings"
	"testing"
)

func TestValidateWebhookPayload_Valid(t *testing.T) {
	body := `{
		"event_type": "payment.completed",
		"tenant_id": "demo-tenant",
		"source": "payment-gateway",
		"data": {"amount": 1500, "currency": "KES"}
	}`

	result, err := ValidateWebhookPayload(body)
	if err != nil {
		t.Fatalf("expected valid payload, got error: %v", err)
	}
	if result.EventType != "payment.completed" {
		t.Errorf("expected event_type payment.completed, got %s", result.EventType)
	}
	if result.TenantID != "demo-tenant" {
		t.Errorf("expected tenant_id demo-tenant, got %s", result.TenantID)
	}
}

func TestValidateWebhookPayload_EmptyBody(t *testing.T) {
	_, err := ValidateWebhookPayload("")
	if err != ErrEmptyBody {
		t.Fatalf("expected ErrEmptyBody, got: %v", err)
	}
}

func TestValidateWebhookPayload_OversizedBody(t *testing.T) {
	body := strings.Repeat("x", MaxPayloadSize+1)
	_, err := ValidateWebhookPayload(body)
	if err == nil {
		t.Fatal("expected error for oversized body")
	}
}

func TestValidateWebhookPayload_InvalidJSON(t *testing.T) {
	_, err := ValidateWebhookPayload("{not valid json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestValidateWebhookPayload_MissingEventType(t *testing.T) {
	body := `{"tenant_id": "test", "data": {"key": "value"}}`
	_, err := ValidateWebhookPayload(body)
	if err == nil {
		t.Fatal("expected error for missing event_type")
	}
}

func TestValidateWebhookPayload_UnknownEventType(t *testing.T) {
	body := `{"event_type": "unknown.event", "tenant_id": "test", "data": {"key": "value"}}`
	_, err := ValidateWebhookPayload(body)
	if err == nil {
		t.Fatal("expected error for unknown event_type")
	}
}

func TestValidateWebhookPayload_InvalidTenantID(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
	}{
		{"path traversal", "../etc/passwd"},
		{"SQL injection", "tenant'; DROP TABLE--"},
		{"too short", "ab"},
		{"special chars", "tenant@evil.com"},
		{"double underscore", "tenant__test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"event_type": "payment.completed", "tenant_id": "` + tt.tenantID + `", "data": {"key": "value"}}`
			_, err := ValidateWebhookPayload(body)
			if err == nil {
				t.Errorf("expected error for tenant_id %q, got nil", tt.tenantID)
			}
		})
	}
}

func TestIsValidTenantID(t *testing.T) {
	valid := []string{"demo-tenant", "tenant_123", "MyTenant", "abc"}
	for _, id := range valid {
		if !isValidTenantID(id) {
			t.Errorf("expected %q to be valid", id)
		}
	}

	invalid := []string{"ab", "", "a b", "tenant/path", "tenant..path"}
	for _, id := range invalid {
		if isValidTenantID(id) {
			t.Errorf("expected %q to be invalid", id)
		}
	}
}

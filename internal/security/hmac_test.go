package security

import (
	"testing"
)

func TestVerifyHMACSignature_Valid(t *testing.T) {
	payload := []byte(`{"event_type":"payment.completed","tenant_id":"test"}`)
	secret := []byte("test-secret-key")

	// Generate a valid signature
	sig := GenerateHMACSignature(payload, secret)

	err := VerifyHMACSignature(payload, sig, secret)
	if err != nil {
		t.Fatalf("expected valid signature, got error: %v", err)
	}
}

func TestVerifyHMACSignature_Invalid(t *testing.T) {
	payload := []byte(`{"event_type":"payment.completed"}`)
	secret := []byte("test-secret-key")

	err := VerifyHMACSignature(payload, "sha256=deadbeef", secret)
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
}

func TestVerifyHMACSignature_Missing(t *testing.T) {
	err := VerifyHMACSignature([]byte("test"), "", []byte("secret"))
	if err != ErrMissingSignature {
		t.Fatalf("expected ErrMissingSignature, got: %v", err)
	}
}

func TestVerifyHMACSignature_BadFormat(t *testing.T) {
	err := VerifyHMACSignature([]byte("test"), "md5=abc123", []byte("secret"))
	if err != ErrInvalidFormat {
		t.Fatalf("expected ErrInvalidFormat, got: %v", err)
	}
}

func TestVerifyHMACSignature_TamperedPayload(t *testing.T) {
	original := []byte(`{"amount":100}`)
	tampered := []byte(`{"amount":999}`)
	secret := []byte("test-secret-key")

	sig := GenerateHMACSignature(original, secret)

	// Verify with tampered payload should fail
	err := VerifyHMACSignature(tampered, sig, secret)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature for tampered payload, got: %v", err)
	}
}

func TestVerifyHMACSignature_WrongSecret(t *testing.T) {
	payload := []byte(`{"event_type":"payment.completed"}`)

	sig := GenerateHMACSignature(payload, []byte("correct-secret"))

	err := VerifyHMACSignature(payload, sig, []byte("wrong-secret"))
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature for wrong secret, got: %v", err)
	}
}

// Benchmark to show constant-time comparison doesn't add overhead
func BenchmarkVerifyHMACSignature(b *testing.B) {
	payload := []byte(`{"event_type":"payment.completed","tenant_id":"bench-tenant","data":{"amount":1500}}`)
	secret := []byte("benchmark-secret-key-256-bits-ok")
	sig := GenerateHMACSignature(payload, secret)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VerifyHMACSignature(payload, sig, secret)
	}
}

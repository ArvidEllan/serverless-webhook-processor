package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrMissingSignature = errors.New("missing webhook signature header")
	ErrInvalidSignature = errors.New("invalid webhook signature")
	ErrInvalidFormat    = errors.New("invalid signature format: expected sha256=<hex>")
)

// VerifyHMACSignature validates an incoming webhook's HMAC-SHA256 signature.
//
// Security considerations:
//   - Uses crypto/hmac.Equal for constant-time comparison (prevents timing attacks)
//   - Expects signature format: "sha256=<hex-encoded-digest>"
//   - Secret should be loaded from AWS Secrets Manager, never hardcoded
func VerifyHMACSignature(payload []byte, signatureHeader string, secret []byte) error {
	if signatureHeader == "" {
		return ErrMissingSignature
	}

	// Parse "sha256=<hex>" format (standard webhook signature format)
	parts := strings.SplitN(signatureHeader, "=", 2)
	if len(parts) != 2 || parts[0] != "sha256" {
		return ErrInvalidFormat
	}

	providedSig, err := hex.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("signature hex decode failed: %w", err)
	}

	// Compute expected HMAC-SHA256
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	expectedSig := mac.Sum(nil)

	// Constant-time comparison — critical for preventing timing side-channels
	if !hmac.Equal(providedSig, expectedSig) {
		return ErrInvalidSignature
	}

	return nil
}

// GenerateHMACSignature creates an HMAC-SHA256 signature for outbound webhooks
// or testing. Returns "sha256=<hex>" format.
func GenerateHMACSignature(payload []byte, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

package security

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// Encryptor handles field-level encryption using AWS KMS.
//
// Why KMS for serverless:
//   - No key management overhead (AWS handles rotation, access control)
//   - IAM-bound: only this Lambda's role can encrypt/decrypt
//   - Audit trail: every encrypt/decrypt call logged in CloudTrail
//   - Envelope encryption: KMS generates data keys, we encrypt locally
type Encryptor struct {
	client *kms.Client
	keyID  string // KMS key ARN or alias
}

// NewEncryptor creates an Encryptor bound to a specific KMS key.
func NewEncryptor(client *kms.Client, keyID string) *Encryptor {
	return &Encryptor{
		client: client,
		keyID:  keyID,
	}
}

// EncryptField encrypts a plaintext string using KMS direct encryption.
// Suitable for payloads under 4KB. For larger payloads, use envelope encryption.
//
// Returns base64-encoded ciphertext for safe storage in DynamoDB.
func (e *Encryptor) EncryptField(ctx context.Context, plaintext string) (string, error) {
	output, err := e.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     aws.String(e.keyID),
		Plaintext: []byte(plaintext),
	})
	if err != nil {
		return "", fmt.Errorf("kms encrypt failed: %w", err)
	}

	return base64.StdEncoding.EncodeToString(output.CiphertextBlob), nil
}

// DecryptField decrypts a base64-encoded ciphertext string using KMS.
func (e *Encryptor) DecryptField(ctx context.Context, ciphertext string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %w", err)
	}

	output, err := e.client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: decoded,
	})
	if err != nil {
		return "", fmt.Errorf("kms decrypt failed: %w", err)
	}

	return string(output.Plaintext), nil
}

// EncryptFieldEnvelope uses envelope encryption for payloads > 4KB.
// Generates a data key via KMS, encrypts locally with AES-GCM, stores
// the encrypted data key alongside the ciphertext.
//
// TODO: Implement for Day 3 if payload sizes warrant it.
// func (e *Encryptor) EncryptFieldEnvelope(ctx context.Context, plaintext []byte) ([]byte, error) {}

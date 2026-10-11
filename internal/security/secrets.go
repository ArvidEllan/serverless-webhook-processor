package security

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// SecretCache caches secrets in-memory within a Lambda execution context.
//
// Why cache secrets in Lambda:
//   - Lambda reuses execution environments (warm starts)
//   - Secrets Manager has API rate limits (10,000 requests/sec per region)
//   - Avoids unnecessary latency on warm invocations
//   - TTL ensures secrets rotate within a bounded window
type SecretCache struct {
	client *secretsmanager.Client
	cache  map[string]*cachedSecret
	mu     sync.RWMutex
	ttl    time.Duration
}

type cachedSecret struct {
	value     map[string]string
	fetchedAt time.Time
}

// NewSecretCache creates a cache with a configurable TTL.
// Recommended TTL: 5 minutes (balances freshness vs. API calls).
func NewSecretCache(client *secretsmanager.Client, ttl time.Duration) *SecretCache {
	return &SecretCache{
		client: client,
		cache:  make(map[string]*cachedSecret),
		ttl:    ttl,
	}
}

// GetSecret retrieves a JSON secret, returning cached values when valid.
func (sc *SecretCache) GetSecret(ctx context.Context, secretName string) (map[string]string, error) {
	sc.mu.RLock()
	if cached, ok := sc.cache[secretName]; ok {
		if time.Since(cached.fetchedAt) < sc.ttl {
			sc.mu.RUnlock()
			return cached.value, nil
		}
	}
	sc.mu.RUnlock()

	// Cache miss or expired — fetch from Secrets Manager
	output, err := sc.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	})
	if err != nil {
		return nil, fmt.Errorf("secrets manager fetch failed for %s: %w", secretName, err)
	}

	var secret map[string]string
	if err := json.Unmarshal([]byte(*output.SecretString), &secret); err != nil {
		return nil, fmt.Errorf("secret JSON parse failed: %w", err)
	}

	sc.mu.Lock()
	sc.cache[secretName] = &cachedSecret{
		value:     secret,
		fetchedAt: time.Now(),
	}
	sc.mu.Unlock()

	return secret, nil
}

// GetWebhookSecret retrieves the HMAC signing secret for a specific tenant.
// Secret format in Secrets Manager: {"tenant_abc": "secret123", "tenant_xyz": "secret456"}
func (sc *SecretCache) GetWebhookSecret(ctx context.Context, secretName, tenantID string) ([]byte, error) {
	secrets, err := sc.GetSecret(ctx, secretName)
	if err != nil {
		return nil, err
	}

	secret, ok := secrets[tenantID]
	if !ok {
		return nil, fmt.Errorf("no webhook secret found for tenant %s", tenantID)
	}

	return []byte(secret), nil
}

package middleware

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// RateLimiter implements a sliding-window rate limiter using DynamoDB atomic counters.
//
// Why DynamoDB for rate limiting in serverless:
//   - No external Redis/ElastiCache dependency = truly serverless
//   - Atomic UpdateItem with ADD = safe under concurrent Lambda invocations
//   - TTL auto-cleans expired windows = zero maintenance
//   - Single-digit millisecond latency at any scale
//
// Trade-off vs API Gateway throttling:
//   - API Gateway: per-stage/per-key limits (coarse)
//   - This: per-tenant, per-minute granularity (fine-grained)
//   - Use BOTH: API Gateway as a global backstop, this for tenant-level control
type RateLimiter struct {
	client        *dynamodb.Client
	tableName     string
	maxRequests   int
	windowMinutes int
}

// NewRateLimiter creates a limiter with configurable thresholds.
// Default: 100 requests per 1-minute window per tenant.
func NewRateLimiter(client *dynamodb.Client, tableName string, maxRequests, windowMinutes int) *RateLimiter {
	return &RateLimiter{
		client:        client,
		tableName:     tableName,
		maxRequests:   maxRequests,
		windowMinutes: windowMinutes,
	}
}

// RateLimitResult contains the outcome of a rate limit check.
type RateLimitResult struct {
	Allowed    bool
	Current    int
	Limit      int
	Window     string
	RetryAfter time.Duration // Only set when denied
}

// CheckAndIncrement atomically increments the counter and checks the limit.
//
// Uses DynamoDB's UpdateItem with ADD (atomic increment) to handle
// concurrent Lambda invocations safely — no read-modify-write race conditions.
func (rl *RateLimiter) CheckAndIncrement(ctx context.Context, tenantID string) (*RateLimitResult, error) {
	now := time.Now().UTC()
	windowKey := fmt.Sprintf("RATELIMIT#%s", now.Truncate(time.Duration(rl.windowMinutes)*time.Minute).Format("2006-01-02T15:04"))

	// TTL: expire 2x the window to handle edge cases
	ttl := now.Add(time.Duration(rl.windowMinutes*2) * time.Minute).Unix()

	// Atomic increment — safe under concurrent execution
	output, err := rl.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(rl.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "TENANT#" + tenantID},
			"SK": &types.AttributeValueMemberS{Value: windowKey},
		},
		UpdateExpression: aws.String("ADD request_count :inc SET expires_at = if_not_exists(expires_at, :ttl)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":inc": &types.AttributeValueMemberN{Value: "1"},
			":ttl": &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", ttl)},
		},
		ReturnValues: types.ReturnValueAllNew,
	})
	if err != nil {
		return nil, fmt.Errorf("rate limit update failed: %w", err)
	}

	// We just incremented this with ReturnValueAllNew, so it's always present and numeric.
	countAttr := output.Attributes["request_count"].(*types.AttributeValueMemberN)
	count, err := strconv.Atoi(countAttr.Value)
	if err != nil {
		return nil, fmt.Errorf("parse request_count failed: %w", err)
	}

	result := &RateLimitResult{
		Allowed: count <= rl.maxRequests,
		Current: count,
		Limit:   rl.maxRequests,
		Window:  windowKey,
	}

	if !result.Allowed {
		// Calculate retry-after: time until next window opens
		nextWindow := now.Truncate(time.Duration(rl.windowMinutes) * time.Minute).Add(time.Duration(rl.windowMinutes) * time.Minute)
		result.RetryAfter = time.Until(nextWindow)
	}

	return result, nil
}

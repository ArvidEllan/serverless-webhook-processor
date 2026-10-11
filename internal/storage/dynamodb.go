package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/ArvidEllan/serverless-webhook-processor/internal/models"
)

// EventStore handles DynamoDB operations for webhook events.
//
// Table Design (single-table pattern):
//
//	PK: EVENT#<event_id>        SK: TENANT#<tenant_id>     → Event record
//	PK: TENANT#<tenant_id>      SK: RATELIMIT#<window>     → Rate limit counter
//
// GSI1 (TenantIndex):
//
//	GSI1PK: TENANT#<tenant_id>  GSI1SK: <created_at>       → Query by tenant + time
//
// Why single-table:
//   - One provisioned table = simpler IAM, lower cost
//   - Tenant isolation via key prefix (no cross-tenant reads possible)
//   - GSI enables per-tenant queries without scans
type EventStore struct {
	client    *dynamodb.Client
	tableName string
	ttlDays   int
}

// NewEventStore creates a store bound to a DynamoDB table.
func NewEventStore(client *dynamodb.Client, tableName string) *EventStore {
	return &EventStore{
		client:    client,
		tableName: tableName,
		ttlDays:   90, // 90-day retention default
	}
}

// PutEvent writes a webhook event with conditional check to ensure idempotency.
//
// Idempotency: Uses a condition expression to reject duplicate event_ids.
// This prevents double-processing when Lambda retries on transient failures.
func (es *EventStore) PutEvent(ctx context.Context, event *models.WebhookEvent) error {
	// Set TTL for automatic expiration
	event.ExpiresAt = time.Now().AddDate(0, 0, es.ttlDays).Unix()

	item, err := attributevalue.MarshalMap(event)
	if err != nil {
		return fmt.Errorf("marshal event failed: %w", err)
	}

	// Prefix keys for single-table design
	item["PK"] = &types.AttributeValueMemberS{Value: "EVENT#" + event.EventID}
	item["SK"] = &types.AttributeValueMemberS{Value: "TENANT#" + event.TenantID}

	// GSI keys for tenant-based queries
	item["GSI1PK"] = &types.AttributeValueMemberS{Value: "TENANT#" + event.TenantID}
	item["GSI1SK"] = &types.AttributeValueMemberS{Value: event.CreatedAt.Format(time.RFC3339)}

	_, err = es.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(es.tableName),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(PK)"), // Idempotency guard
	})
	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return fmt.Errorf("duplicate event %s: %w", event.EventID, ErrDuplicateEvent)
		}
		return fmt.Errorf("dynamodb put failed: %w", err)
	}

	return nil
}

// GetEventsByTenant queries events for a specific tenant within a time range.
// Uses GSI1 to avoid scanning the entire table.
func (es *EventStore) GetEventsByTenant(ctx context.Context, tenantID string, since time.Time) ([]models.WebhookEvent, error) {
	output, err := es.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(es.tableName),
		IndexName:              aws.String("GSI1-TenantIndex"),
		KeyConditionExpression: aws.String("GSI1PK = :pk AND GSI1SK >= :since"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":    &types.AttributeValueMemberS{Value: "TENANT#" + tenantID},
			":since": &types.AttributeValueMemberS{Value: since.Format(time.RFC3339)},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("query tenant events failed: %w", err)
	}

	var events []models.WebhookEvent
	if err := attributevalue.UnmarshalListOfMaps(output.Items, &events); err != nil {
		return nil, fmt.Errorf("unmarshal events failed: %w", err)
	}

	return events, nil
}

var ErrDuplicateEvent = errors.New("event already exists")

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/ArvidEllan/serverless-webhook-processor/internal/middleware"
	"github.com/ArvidEllan/serverless-webhook-processor/internal/models"
	"github.com/ArvidEllan/serverless-webhook-processor/internal/security"
	"github.com/ArvidEllan/serverless-webhook-processor/internal/storage"
)

// WebhookHandler processes webhooks through rate limiting, signature verification,
// payload validation, encryption, and idempotent persistence, in that order.
type WebhookHandler struct {
	logger      *zap.Logger
	store       *storage.EventStore
	encryptor   *security.Encryptor
	secrets     *security.SecretCache
	rateLimiter *middleware.RateLimiter
	secretName  string
}

// NewWebhookHandler wires up all dependencies.
// Dependencies are injected — makes testing straightforward.
func NewWebhookHandler(
	logger *zap.Logger,
	store *storage.EventStore,
	encryptor *security.Encryptor,
	secrets *security.SecretCache,
	rateLimiter *middleware.RateLimiter,
) *WebhookHandler {
	return &WebhookHandler{
		logger:      logger,
		store:       store,
		encryptor:   encryptor,
		secrets:     secrets,
		rateLimiter: rateLimiter,
		secretName:  os.Getenv("WEBHOOK_SECRET_NAME"),
	}
}

// Handle is the Lambda entry point for API Gateway proxy events.
func (h *WebhookHandler) Handle(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	startTime := time.Now()
	requestID := request.RequestContext.RequestID

	h.logger.Info("webhook received",
		zap.String("request_id", requestID),
		zap.String("source_ip", request.RequestContext.Identity.SourceIP),
		zap.String("user_agent", request.Headers["user-agent"]),
	)

	// --- 1. Extract tenant ID from path or header ---
	tenantID := request.PathParameters["tenantId"]
	if tenantID == "" {
		tenantID = request.Headers["x-tenant-id"]
	}
	if tenantID == "" {
		return h.errorResponse(http.StatusBadRequest, "missing tenant identifier", requestID)
	}

	// --- 2. Rate limiting (before any expensive operations) ---
	rlResult, err := h.rateLimiter.CheckAndIncrement(ctx, tenantID)
	if err != nil {
		h.logger.Error("rate limit check failed", zap.Error(err))
		// Fail open for rate limiter errors (availability > strict limiting)
		// In production, decide based on your threat model
	} else if !rlResult.Allowed {
		h.logger.Warn("rate limit exceeded",
			zap.String("tenant_id", tenantID),
			zap.Int("current", rlResult.Current),
			zap.Int("limit", rlResult.Limit),
		)
		return h.rateLimitResponse(rlResult, requestID)
	}

	// --- 3. HMAC signature verification ---
	signature := request.Headers["x-webhook-signature"]
	if signature == "" {
		// Also check lowercase (API Gateway normalizes inconsistently)
		signature = request.Headers["X-Webhook-Signature"]
	}

	webhookSecret, err := h.secrets.GetWebhookSecret(ctx, h.secretName, tenantID)
	if err != nil {
		h.logger.Error("failed to retrieve webhook secret",
			zap.String("tenant_id", tenantID),
			zap.Error(err),
		)
		// Don't reveal whether the tenant exists
		return h.errorResponse(http.StatusUnauthorized, "authentication failed", requestID)
	}

	if err := security.VerifyHMACSignature([]byte(request.Body), signature, webhookSecret); err != nil {
		h.logger.Warn("signature verification failed",
			zap.String("tenant_id", tenantID),
			zap.Error(err),
		)
		// Generic error — don't reveal why auth failed
		return h.errorResponse(http.StatusUnauthorized, "authentication failed", requestID)
	}

	// --- 4. Validate and sanitize payload ---
	validated, err := middleware.ValidateWebhookPayload(request.Body)
	if err != nil {
		h.logger.Warn("payload validation failed",
			zap.String("tenant_id", tenantID),
			zap.Error(err),
		)
		return h.errorResponse(http.StatusBadRequest, "invalid payload", requestID)
	}

	// --- 5. Encrypt sensitive payload data ---
	encryptedData, err := h.encryptor.EncryptField(ctx, string(validated.Data))
	if err != nil {
		h.logger.Error("encryption failed", zap.Error(err))
		return h.errorResponse(http.StatusInternalServerError, "processing error", requestID)
	}

	// --- 6. Persist with idempotency ---
	eventID := uuid.New().String()
	event := &models.WebhookEvent{
		EventID:   eventID,
		TenantID:  tenantID,
		EventType: validated.EventType,
		Payload:   encryptedData,
		Source:    validated.Source,
		Status:    models.StatusReceived,
		Metadata:  validated.Metadata,
		CreatedAt: time.Now().UTC(),
	}

	if err := h.store.PutEvent(ctx, event); err != nil {
		if errors.Is(err, storage.ErrDuplicateEvent) {
			// Idempotent: return success for duplicate
			h.logger.Info("duplicate event ignored", zap.String("event_id", eventID))
			return h.successResponse(eventID, "accepted (duplicate)", requestID)
		}
		h.logger.Error("storage failed", zap.Error(err))
		return h.errorResponse(http.StatusInternalServerError, "processing error", requestID)
	}

	duration := time.Since(startTime)
	h.logger.Info("webhook processed",
		zap.String("event_id", eventID),
		zap.String("tenant_id", tenantID),
		zap.String("event_type", validated.EventType),
		zap.Duration("duration", duration),
	)

	return h.successResponse(eventID, "accepted", requestID)
}

// --- Response helpers ---
// Principle: return MINIMAL information. Never leak internal state.

func (h *WebhookHandler) successResponse(eventID, message, requestID string) (events.APIGatewayProxyResponse, error) {
	body, _ := json.Marshal(models.WebhookResponse{
		EventID: eventID,
		Status:  "accepted",
		Message: message,
	})
	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusAccepted,
		Headers:    securityHeaders(requestID),
		Body:       string(body),
	}, nil
}

func (h *WebhookHandler) errorResponse(statusCode int, message, requestID string) (events.APIGatewayProxyResponse, error) {
	body, _ := json.Marshal(map[string]string{
		"error": message,
	})
	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers:    securityHeaders(requestID),
		Body:       string(body),
	}, nil
}

func (h *WebhookHandler) rateLimitResponse(result *middleware.RateLimitResult, requestID string) (events.APIGatewayProxyResponse, error) {
	headers := securityHeaders(requestID)
	headers["Retry-After"] = fmt.Sprintf("%d", int(result.RetryAfter.Seconds()))
	headers["X-RateLimit-Limit"] = fmt.Sprintf("%d", result.Limit)
	headers["X-RateLimit-Remaining"] = "0"

	body, _ := json.Marshal(map[string]string{
		"error": "rate limit exceeded",
	})
	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusTooManyRequests,
		Headers:    headers,
		Body:       string(body),
	}, nil
}

// securityHeaders returns hardened response headers.
func securityHeaders(requestID string) map[string]string {
	return map[string]string{
		"Content-Type":              "application/json",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Cache-Control":             "no-store",
		"X-Request-Id":              requestID,
	}
}

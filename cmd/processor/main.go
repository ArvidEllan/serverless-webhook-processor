package main

import (
	"context"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"go.uber.org/zap"

	"github.com/ArvidEllan/serverless-webhook-processor/internal/handler"
	"github.com/ArvidEllan/serverless-webhook-processor/internal/middleware"
	"github.com/ArvidEllan/serverless-webhook-processor/internal/security"
	"github.com/ArvidEllan/serverless-webhook-processor/internal/storage"
)

// Dependencies are initialized here, outside Handle, so Lambda reuses them
// across warm invocations instead of recreating them on every request.
func main() {
	// --- Structured logging ---
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("failed to init logger: %v", err)
	}
	defer logger.Sync()

	// --- AWS SDK configuration ---
	// Uses Lambda's execution role credentials automatically
	// X-Ray tracing is enabled via SAM template, SDK picks it up
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		logger.Fatal("failed to load AWS config", zap.Error(err))
	}

	// --- Service clients (created once, reused on warm starts) ---
	dynamoClient := dynamodb.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)
	secretsClient := secretsmanager.NewFromConfig(cfg)

	// --- Environment configuration ---
	tableName := envString("DYNAMODB_TABLE", "webhook-events")
	kmsKeyID := os.Getenv("KMS_KEY_ID")
	rateLimit := envInt("RATE_LIMIT_PER_MINUTE", 100)

	if kmsKeyID == "" {
		logger.Fatal("KMS_KEY_ID environment variable is required")
	}

	// --- Wire dependencies ---
	eventStore := storage.NewEventStore(dynamoClient, tableName)
	encryptor := security.NewEncryptor(kmsClient, kmsKeyID)
	secretCache := security.NewSecretCache(secretsClient, 5*time.Minute)
	rateLimiter := middleware.NewRateLimiter(dynamoClient, tableName, rateLimit, 1)

	webhookHandler := handler.NewWebhookHandler(
		logger,
		eventStore,
		encryptor,
		secretCache,
		rateLimiter,
	)

	// --- Start Lambda runtime ---
	lambda.Start(webhookHandler.Handle)
}

func envString(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

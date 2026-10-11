.PHONY: build clean test deploy local lint

# ==============================================================
# Build Configuration
# ==============================================================
BINARY_NAME    = bootstrap
HANDLER_PATH   = ./cmd/processor
OUTPUT_DIR     = .aws-sam/build
TEMPLATE       = deployments/template.yaml
STACK_NAME     = serverless-webhook-processor
REGION         ?= af-south-1
STAGE          ?= dev

# Go build flags:
#   - CGO_ENABLED=0: Static binary (no C dependencies — required for Lambda)
#   - GOARCH=arm64:  Graviton processors (20% cheaper than x86)
#   - GOOS=linux:    Lambda runs on Amazon Linux
#   - ldflags:       Strip debug info → smaller binary → faster cold starts
GO_BUILD_FLAGS = CGO_ENABLED=0 GOOS=linux GOARCH=arm64

# ==============================================================
# Build
# ==============================================================
build:
	@echo "🔨 Building Go binary for Lambda (arm64)..."
	$(GO_BUILD_FLAGS) go build -ldflags="-s -w" -tags lambda.norpc -o $(BINARY_NAME) $(HANDLER_PATH)
	@echo "📦 Binary size: $$(du -h $(BINARY_NAME) | cut -f1)"
	@echo "✅ Build complete"

# ==============================================================
# Test
# ==============================================================
test:
	@echo "🧪 Running tests..."
	go test -v -race -cover ./...

test-coverage:
	@echo "📊 Generating coverage report..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "✅ Coverage report: coverage.html"

# ==============================================================
# Local Development
# ==============================================================
local: build
	@echo "🚀 Starting local API (SAM)..."
	sam local start-api \
		--template $(TEMPLATE) \
		--env-vars deployments/env.json \
		--warm-containers EAGER

invoke-local: build
	@echo "⚡ Invoking function locally..."
	sam local invoke WebhookProcessorFunction \
		--template $(TEMPLATE) \
		--event scripts/test-event.json \
		--env-vars deployments/env.json

# ==============================================================
# Deploy
# ==============================================================
deploy: build
	@echo "🚀 Deploying to AWS ($(STAGE))..."
	sam deploy \
		--template-file $(TEMPLATE) \
		--stack-name $(STACK_NAME)-$(STAGE) \
		--region $(REGION) \
		--capabilities CAPABILITY_IAM \
		--parameter-overrides StageName=$(STAGE) \
		--resolve-s3 \
		--no-confirm-changeset

deploy-guided: build
	sam deploy --guided --template-file $(TEMPLATE)

# ==============================================================
# Load Testing
# ==============================================================
load-test:
	@echo "📈 Running load test (100 RPS for 60s)..."
	k6 run scripts/load-test.js

# ==============================================================
# Utilities
# ==============================================================
lint:
	@echo "🔍 Linting..."
	golangci-lint run ./...

clean:
	@echo "🧹 Cleaning..."
	rm -f $(BINARY_NAME) coverage.out coverage.html
	rm -rf .aws-sam

logs:
	sam logs --stack-name $(STACK_NAME)-$(STAGE) --tail

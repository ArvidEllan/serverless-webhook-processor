# Serverless Webhook Processor

> **"Serverless Without the Limits: Designing AWS Systems That Scale"**
>
> Demo project for the technical session — Oct 31, 2026

A production-grade, multi-tenant webhook processor built on AWS serverless with layered security. Demonstrates how to design systems that scale from 0 to thousands of requests per second with zero infrastructure management.

## Architecture

```
                         ┌──────────────────────────────────────────────┐
                         │              Security Pipeline              │
                         │                                              │
  Client ──► API Gateway ──► Lambda ──┬──► Rate Limiter (DynamoDB)     │
              (throttle)    (Go)      ├──► HMAC Signature Verify       │
              (WAF-ready)             ├──► Payload Validation          │
                                      ├──► KMS Field Encryption       │
                                      └──► DynamoDB (single-table)    │
                         │                                              │
                         │  Observability: X-Ray ─── CloudWatch ─── Alarms│
                         └──────────────────────────────────────────────┘
```

## Security Layers (Defense in Depth)

| Layer | What | Why |
|-------|------|-----|
| API Gateway Throttling | Global rate limit (200 burst / 100 sustained) | DDoS backstop |
| Tenant Rate Limiting | DynamoDB atomic counters (100 req/min/tenant) | Abuse prevention |
| HMAC-SHA256 Signatures | Constant-time verification per tenant | Authentication + integrity |
| Payload Validation | Size limits, schema checks, tenant ID sanitization | Input defense |
| KMS Field Encryption | Customer-managed key, auto-rotation | Data protection at rest |
| IAM Least Privilege | Scoped to specific table, key, secret | Blast radius containment |
| Security Headers | HSTS, X-Frame-Options, no-cache | Response hardening |
| DynamoDB Encryption | SSE enabled (AWS-managed) | Storage encryption |
| Idempotency Guards | Conditional PutItem (no duplicates) | Retry safety |
| TTL Expiration | Auto-delete after 90 days | Data minimization |

## Prerequisites

- Go 1.22+
- AWS SAM CLI
- AWS CLI (configured)
- k6 (for load testing)
- Docker (for SAM local)

## Quick Start

```bash
# Build
make build

# Test
make test

# Deploy (first time)
make deploy-guided

# Deploy (subsequent)
make deploy STAGE=dev

# Load test
API_ENDPOINT=https://xxx.execute-api.af-south-1.amazonaws.com/dev \
WEBHOOK_SECRET=your-secret \
  make load-test

# View logs
make logs
```

## Project Structure

```
.
├── cmd/processor/          # Lambda entry point (init + DI)
│   └── main.go
├── internal/
│   ├── handler/            # Request processing pipeline
│   │   └── webhook.go
│   ├── middleware/          # Rate limiting, validation
│   │   ├── ratelimit.go
│   │   ├── validator.go
│   │   └── validator_test.go
│   ├── models/             # Domain types
│   │   └── event.go
│   ├── security/           # HMAC, KMS encryption, secrets
│   │   ├── encryption.go
│   │   ├── hmac.go
│   │   ├── hmac_test.go
│   │   └── secrets.go
│   └── storage/            # DynamoDB operations
│       └── dynamodb.go
├── deployments/
│   ├── template.yaml       # SAM / CloudFormation (full IaC)
│   └── env.json            # Local environment config
├── scripts/
│   ├── load-test.js        # k6 load test
│   └── test-event.json     # SAM local test event
├── Makefile
├── go.mod
└── README.md
```

## Key Design Decisions

### Why Go?
- **100-300ms cold starts** (vs 800ms-1.5s Python)
- Single static binary → smaller attack surface
- Excellent stdlib crypto primitives
- Memory-efficient → cheaper Lambda execution

### Why Single-Table DynamoDB?
- One table = one IAM policy = simpler security boundary
- Tenant isolation via key prefix (no cross-tenant reads possible)
- GSI enables per-tenant queries without table scans
- PAY_PER_REQUEST = auto-scales, no capacity planning

### Why ARM64 (Graviton)?
- 20% cheaper per ms of Lambda execution
- 10-15% faster for Go workloads
- Same API, zero code changes

## Demo Script (Oct 31)

1. **Show architecture** → explain each security layer
2. **Deploy** → `make deploy` (show SAM output)
3. **Send test webhook** → `curl` with HMAC signature
4. **Show rejection** → tampered signature → 401
5. **Run load test** → k6 ramps to 200 RPS
6. **Show CloudWatch** → Lambda concurrency, DynamoDB throughput, latency
7. **Show cost** → compare to EC2/ECS equivalent
8. **Code walkthrough** → handler pipeline, security patterns

## Cost Estimate (at scale)

| Component | 1M events/month | 10M events/month |
|-----------|-----------------|-------------------|
| Lambda (256MB, 200ms avg) | ~$0.63 | ~$6.30 |
| API Gateway | ~$3.50 | ~$35.00 |
| DynamoDB (on-demand) | ~$1.25 | ~$12.50 |
| KMS | ~$1.00 | ~$1.00 |
| Secrets Manager | ~$0.40 | ~$0.40 |
| **Total** | **~$6.78** | **~$55.20** |

Compare: equivalent EC2 setup → ~$50-100/month minimum (always running).

## License

MIT

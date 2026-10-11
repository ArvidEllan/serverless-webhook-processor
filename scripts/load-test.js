/**
 * k6 Load Test — Serverless Webhook Processor
 *
 * Demonstrates scaling behavior for Oct 31 session:
 *   Stage 1: Ramp from 0 → 50 RPS  (warm-up)
 *   Stage 2: Hold 50 RPS for 30s   (steady state)
 *   Stage 3: Spike to 200 RPS      (burst traffic)
 *   Stage 4: Hold 200 RPS for 30s  (sustained load)
 *   Stage 5: Cool down to 10 RPS   (scale-in)
 *
 * Run: k6 run scripts/load-test.js
 * With output: k6 run --out json=results.json scripts/load-test.js
 */

import http from 'k6/http';
import crypto from 'k6/crypto';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// ============================================================
// Configuration
// ============================================================
const API_ENDPOINT = __ENV.API_ENDPOINT || 'https://YOUR_API_ID.execute-api.af-south-1.amazonaws.com/dev';
const WEBHOOK_SECRET = __ENV.WEBHOOK_SECRET || 'replace-with-secure-random-secret';
const TENANT_ID = __ENV.TENANT_ID || 'demo-tenant';

// Custom metrics for the demo dashboard
const webhookSuccess = new Rate('webhook_success_rate');
const webhookLatency = new Trend('webhook_latency_ms');
const rateLimited = new Counter('rate_limited_count');

// ============================================================
// Load Profile — designed to tell a scaling story
// ============================================================
export const options = {
  stages: [
    { duration: '15s', target: 50 },   // Ramp up
    { duration: '30s', target: 50 },   // Steady state
    { duration: '10s', target: 200 },  // Spike!
    { duration: '30s', target: 200 },  // Sustained high load
    { duration: '15s', target: 10 },   // Cool down
  ],
  thresholds: {
    'http_req_duration': ['p(95)<500'],        // 95th percentile under 500ms
    'webhook_success_rate': ['rate>0.95'],      // 95% success rate
    'http_req_failed': ['rate<0.05'],           // Less than 5% errors
  },
};

// ============================================================
// Generate HMAC signature (matches server-side verification)
// ============================================================
function signPayload(payload) {
  const hmacDigest = crypto.hmac('sha256', WEBHOOK_SECRET, payload, 'hex');
  return `sha256=${hmacDigest}`;
}

// ============================================================
// Generate realistic webhook payload
// ============================================================
function generatePayload() {
  const eventTypes = [
    'payment.completed',
    'payment.failed',
    'transfer.initiated',
    'transfer.completed',
    'account.updated',
  ];

  const payload = JSON.stringify({
    event_type: eventTypes[Math.floor(Math.random() * eventTypes.length)],
    tenant_id: TENANT_ID,
    source: 'load-test',
    data: {
      transaction_id: `txn_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      amount: Math.floor(Math.random() * 100000) + 100,
      currency: 'KES',
      merchant: 'Load Test Merchant',
      timestamp: new Date().toISOString(),
    },
    metadata: {
      environment: 'load-test',
      iteration: `${__ITER}`,
    },
  });

  return payload;
}

// ============================================================
// Main test function — runs per virtual user
// ============================================================
export default function () {
  const payload = generatePayload();
  const signature = signPayload(payload);

  const response = http.post(
    `${API_ENDPOINT}/webhooks/${TENANT_ID}`,
    payload,
    {
      headers: {
        'Content-Type': 'application/json',
        'x-webhook-signature': signature,
        'x-tenant-id': TENANT_ID,
      },
      tags: { name: 'webhook_post' },
    }
  );

  // Track metrics
  webhookLatency.add(response.timings.duration);

  const success = check(response, {
    'status is 202': (r) => r.status === 202,
    'has event_id': (r) => {
      try {
        return JSON.parse(r.body).event_id !== undefined;
      } catch {
        return false;
      }
    },
    'latency < 500ms': (r) => r.timings.duration < 500,
  });

  webhookSuccess.add(success);

  if (response.status === 429) {
    rateLimited.add(1);
  }

  // Slight pause between requests per VU
  sleep(0.1);
}

// ============================================================
// Summary — printed at the end of the test
// ============================================================
export function handleSummary(data) {
  const summary = {
    total_requests: data.metrics.http_reqs.values.count,
    success_rate: `${(data.metrics.webhook_success_rate.values.rate * 100).toFixed(1)}%`,
    p50_latency: `${data.metrics.http_req_duration.values['p(50)'].toFixed(0)}ms`,
    p95_latency: `${data.metrics.http_req_duration.values['p(95)'].toFixed(0)}ms`,
    p99_latency: `${data.metrics.http_req_duration.values['p(99)'].toFixed(0)}ms`,
    rate_limited: data.metrics.rate_limited_count ? data.metrics.rate_limited_count.values.count : 0,
  };

  console.log('\n📊 Load Test Results:');
  console.log(JSON.stringify(summary, null, 2));

  return {
    stdout: JSON.stringify(summary, null, 2),
  };
}

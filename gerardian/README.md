# gerardian 

Lightweight security engine for detecting risky transactions, user activity, and inventory anomalies in distributed systems.

---

## What This Does

Use gerardian to:

* Block **fraudulent orders**
* Detect **suspicious user behavior**
* Monitor **inventory anomalies**

---

## Quick Start (Ordering System Example)

### 1. Install

```bash
npm install gerardian
```

### 2. Initialize

```javascript
const { Engine } = require('gerardian');

const security = new Engine({
  apiKey: process.env.GERARDIAN_KEY,
  riskThreshold: 75,       // block if risk >= 75
  failMode: 'fail-closed'  // block if system fails
});
```

### 3. Use in Order Flow

```javascript
const handleOrder = async (order) => {
  const result = await security.analyzeTransaction(order);

  if (result.status === 'blocked') {
    throw new Error('High-risk transaction');
  }

  // continue order processing
};
```

---

## Required Order Format

```javascript
{
  orderId: "order-123",
  amount: 150.50,
  userId: "user-456"
}
```

Optional:

```javascript
{
  currency: "USD",
  metadata: {
    ipCountry: "US",
    deviceId: "device-789"
  }
}
```

---

## What You Get Back

```javascript
{
  status: "approved" | "blocked",
  assessment: {
    riskScore: 0-100,
    triggers: ["GEO_MISMATCH", "VELOCITY_EXCEEDED"]
  },
  traceId: "for debugging"
}
```

---

## Decision Rule (Simple)

| Risk Score | Action |
| ---------- | ------ |
| < 75       | Allow  |
| ≥ 75       | Block  |

---

## Check User Activity (Optional)

```javascript
await security.validateUserActivity(activityLogs);
```

Use this for:

* login monitoring
* session validation

---

## Generate Reports (Optional)

```javascript
await security.generateSecurityReport({
  timeframe: "24h"
});
```

---

## Key Config

```javascript
new Engine({
  riskThreshold: 75,
  failMode: 'fail-open' | 'fail-closed'
});
```

* **fail-open** → allow if system fails
* **fail-closed** → block if system fails

---

## Where It Fits

```
Order Request
     ↓
gerardian (risk check)
     ↓
Allow / Block
     ↓
Order Processing
```

---

## Error Handling

```javascript
try {
  await security.analyzeTransaction(order);
} catch (e) {
  // invalid input or system error
}
```

---

## Utilities (Optional)

```javascript
const { sanitizeInput, hashData } = require('gerardian');
```

---

## TL;DR

1. Initialize Engine
2. Call `analyzeTransaction(order)`
3. Block if `status === 'blocked'`
4. Continue business logic



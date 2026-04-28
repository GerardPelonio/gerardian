# gerardian 🛡️

A robust, framework-agnostic security middleware and monitoring SDK designed to safeguard distributed retail and supply chain applications.

**Version:** 1.0.0-stable  
**Authors:** De Belen, Delfino, Pelonio

## Overview

gerardian provides real-time anomaly detection and risk scoring for:
- **Transaction Flows** - Detect payment fraud and velocity-based attacks
- **User Authentication** - Identify account takeover (ATO) and credential stuffing
- **Inventory Movements** - Catch abnormal stock depletion and ghost inventory

## Installation

```bash
npm install gerardian
```

## Quick Start

### Basic Integration (Express.js Example)

```javascript
const gerardian = require('gerardian');

// 1. Initialize the SDK
const security = new gerardian.Engine({
  apiKey: process.env.GERARDIAN_KEY,
  riskThreshold: 75, // Block transactions with risk score >= 75
  failMode: 'fail-closed' // 'fail-open' or 'fail-closed'
});

// 2. Middleware Usage
const handleTransaction = async (req, res) => {
  const orderData = req.body;

  // 3. Analyze in real-time
  const assessment = await security.analyzeTransaction(orderData);

  if (assessment.status === 'blocked') {
    return res.status(403).json({ 
      error: 'Transaction flagged as high risk',
      traceId: assessment.traceId 
    });
  }

  // Proceed with business logic...
  res.json({ success: true, orderId: orderData.orderId });
};
```

## Core API

### 1. analyzeTransaction(orderData)

Analyzes incoming transaction details for financial anomalies.

**Parameters:**
```javascript
{
  orderId: "order-123",           // Required: String
  amount: 150.50,                 // Required: Positive number
  userId: "user-456",             // Required: UUID or user ID
  currency: "USD",                // Optional: Currency code
  metadata: {                     // Optional: Additional data
    ipCountry: "US",
    deviceId: "device-789"
  }
}
```

**Returns:**
```javascript
{
  traceId: "sec-1234567890-abc",
  timestamp: "2026-04-28T12:00:00Z",
  status: "approved" | "blocked" | "error",
  assessment: {
    riskScore: 45,                // 0-100
    action: "ALLOW" | "BLOCK" | "ERROR",
    triggers: [
      "GEO_MISMATCH",
      "VELOCITY_EXCEEDED",
      "AMOUNT_ANOMALY"
    ]
  },
  flags: ["GEO_MISMATCH"],
  message: "Transaction approved"
}
```

### 2. validateUserActivity(logs)

Monitors authentication behaviors and session patterns.

**Parameters:**
```javascript
[
  {
    timestamp: "2026-04-28T11:58:00Z",
    ipAddress: "192.168.1.1",
    deviceId: "device-123",
    userAgent: "Mozilla/5.0...",  // Optional
    sessionId: "session-456"      // Optional
  }
]
```

**Returns:**
```javascript
{
  traceId: "sec-1234567890-abc",
  timestamp: "2026-04-28T12:00:00Z",
  isSuspicious: false,
  confidence: 0.15,               // 0-1.0
  anomalies: ["DEVICE_MISMATCH"],
  logCount: 5,
  message: "Activity appears normal"
}
```

### 3. generateSecurityReport(config)

Compiles interception data for administrative review or analytics dashboards.

**Parameters:**
```javascript
{
  timeframe: "24h",               // "5m", "1h", "24h", "7d"
  format: "json" | "csv"          // Output format
}
```

**Returns:** Structured dataset with summary statistics and threat data.

## Configuration Options

```javascript
new gerardian.Engine({
  apiKey: process.env.GERARDIAN_KEY,    // API key for authentication
  riskThreshold: 75,                    // Risk score threshold for blocking
  failMode: 'fail-closed',              // 'fail-open': Allow on error
                                        // 'fail-closed': Block on error
  rateLimitWindow: 60000,               // Rate limit window (ms)
  rateLimitMaxRequests: 1000            // Max requests per window
});
```

## Standardized Response Schema

All SDK outputs follow this JSON contract:

```json
{
  "traceId": "sec-9901-af",
  "timestamp": "2026-04-23T11:58:01Z",
  "assessment": {
    "riskScore": 88,
    "action": "BLOCK",
    "triggers": ["GEO_MISMATCH", "VELOCITY_EXCEEDED"]
  }
}
```

## Security Features

### Input Validation
Every method call passes through strict schema validation. Invalid inputs throw `GerardianValidationError`.

### Rate Limiting
Built-in DDoS and brute-force protection on security endpoints.

### Error Handling
- **fail-open:** Allows transactions to pass if SDK is unreachable (prioritizes UX)
- **fail-closed:** Blocks transactions if SDK fails (prioritizes security)

### Data Sanitization
All inputs are automatically sanitized to prevent injection attacks.

## Utility Functions

gerardian exports utility functions for common security operations:

```javascript
const { 
  sanitizeInput,
  hashData,
  encryptData,
  maskSensitiveData,
  isValidUUID,
  isValidIP
} = require('gerardian');

// Sanitize user input
const clean = sanitizeInput(userInput);

// Hash sensitive data
const hashed = hashData(password);

// Mask for logging
const masked = maskSensitiveData(creditCard);
```

## Architecture

gerardian acts as a middleware layer between your application logic and data persistence:

```
Request → gerardian Engine → Risk Assessment → Decision (ALLOW/BLOCK)
                                                      ↓
                                              Business Logic
                                                      ↓
                                              Data Persistence
```

## Integration Examples

### NestJS

```typescript
import { Injectable } from '@nestjs/common';
import { Engine } from 'gerardian';

@Injectable()
export class SecurityService {
  private engine: Engine;

  constructor() {
    this.engine = new Engine({ riskThreshold: 75 });
  }

  async checkTransaction(order: any) {
    return await this.engine.analyzeTransaction(order);
  }
}
```

### Standalone

```javascript
const gerardian = require('gerardian');

(async () => {
  const engine = new gerardian.Engine();
  
  const result = await engine.analyzeTransaction({
    orderId: 'order-1',
    amount: 99.99,
    userId: 'user-1'
  });
  
  console.log(result);
})();
```

## Error Handling

```javascript
const { GerardianValidationError, Engine } = require('gerardian');

try {
  const result = await engine.analyzeTransaction(orderData);
  if (result.status === 'error') {
    console.error('Security check failed:', result.error);
  }
} catch (error) {
  if (error instanceof GerardianValidationError) {
    console.error('Invalid input:', error.message);
  }
}
```

## Testing

Run the test suite:

```bash
npm test
```

## Performance Considerations

- Transaction history kept to 100 per user for efficiency
- Activity history limited to 500 entries per IP
- Request timestamps collected for rate limiting analysis
- Automatic cleanup of stale data

## Future Enhancements

- [ ] WebSocket support for real-time monitoring
- [ ] Machine learning-based risk scoring
- [ ] Geographical IP database integration
- [ ] Multi-factor authentication patterns
- [ ] Blockchain transaction verification

## License

MIT

## Support

For issues and feature requests, visit: https://github.com/yourusername/gerardian/issues

---

**Built with security in mind. Designed for scale.** 🔐

/**
 * Express.js Integration Example
 * Run with: node express-test.js
 * Then test with: curl -X POST http://localhost:3000/transaction -H "Content-Type: application/json" -d '{"orderId":"order-1","amount":150,"userId":"user-1"}'
 */

const express = require('express');
const gerardian = require('../src/index');

const app = express();
app.use(express.json());

// Initialize security engine
const security = new gerardian.Engine({
  riskThreshold: 75,
  failMode: 'fail-closed'
});

// Middleware to check transactions
app.post('/transaction', async (req, res) => {
  const assessment = await security.analyzeTransaction(req.body);

  if (assessment.status === 'blocked') {
    return res.status(403).json({
      error: 'Transaction blocked',
      traceId: assessment.traceId,
      riskScore: assessment.assessment.riskScore
    });
  }

  res.json({
    success: true,
    traceId: assessment.traceId,
    riskScore: assessment.assessment.riskScore
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'gerardian active' });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`✅ gerardian test server running on http://localhost:${PORT}`);
  console.log('\nTest endpoints:');
  console.log('  GET  http://localhost:3000/health');
  console.log('  POST http://localhost:3000/transaction');
  console.log('\nExample POST body:');
  console.log('  {"orderId":"order-1","amount":150,"userId":"user-1"}');
});

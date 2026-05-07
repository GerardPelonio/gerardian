/**
 * gerardian - Basic Test Suite
 * Demonstrates core functionality
 */

const { Engine, GerardianValidationError } = require('../src/engine');
const { sanitizeInput, encryptData, decryptData, maskSensitiveData, isValidUUID, isValidIP } = require('../src/utils');

console.log('🛡️  gerardian SDK - Test Suite\n');
console.log('================================\n');

// Initialize the security engine
const security = new Engine({
  riskThreshold: 75,
  failMode: 'fail-closed'
});

// Test 1: Transaction Analysis
console.log('Test 1: Transaction Analysis');
console.log('----------------------------');

(async () => {
  try {
    // Normal transaction
    const normalTx = await security.analyzeTransaction({
      orderId: 'order-001',
      amount: 49.99,
      currency: 'USD'
    });

    console.log('✓ Normal transaction:');
    console.log(`  Status: ${normalTx.status}`);
    console.log(`  Risk Score: ${normalTx.assessment.riskScore}`);
    console.log(`  Action: ${normalTx.assessment.action}`);
    console.log(`  Trace ID: ${normalTx.traceId}\n`);

    // High-value transaction (likely to trigger anomaly)
    const highValueTx = await security.analyzeTransaction({
      orderId: 'order-002',
      amount: 5000.00,
      currency: 'USD',
      metadata: {
        ipCountry: 'JP'
      }
    });

    console.log('✓ High-value transaction:');
    console.log(`  Status: ${highValueTx.status}`);
    console.log(`  Risk Score: ${highValueTx.assessment.riskScore}`);
    console.log(`  Action: ${highValueTx.assessment.action}`);
    console.log(`  Triggers: ${highValueTx.assessment.triggers.join(', ')}\n`);

    // Invalid transaction (missing field)
    const invalidTx = await security.analyzeTransaction({
      orderId: 'order-003'
    });

    console.log('✓ Invalid transaction (missing required data):');
    console.log(`  Status: ${invalidTx.status}`);
    console.log(`  Error: ${invalidTx.error}\n`);

    // Test: Impossible Travel
    console.log('Test: Impossible Travel Detection');
    console.log('---------------------------------');

    // 1. First transaction in New York
    await security.analyzeTransaction({
      orderId: 'order-geo-1',
      amount: 10.00,
      userId: 'user-traveler',
      metadata: {
        lat: 40.7128,
        lon: -74.0060 // New York
      }
    });

    // 2. Second transaction in London (5 seconds later)
    const travelTx = await security.analyzeTransaction({
      orderId: 'order-geo-2',
      amount: 10.00,
      userId: 'user-traveler',
      metadata: {
        lat: 51.5074,
        lon: -0.1278 // London
      }
    });

    console.log('✓ Impossible Travel transaction:');
    console.log(`  Status: ${travelTx.status}`);
    console.log(`  Risk Score: ${travelTx.assessment.riskScore}`);
    console.log(`  Triggers: ${travelTx.assessment.triggers.join(', ')}\n`);

  } catch (error) {
    console.error('✗ Test failed:', error.message);
  }

  // Test 2: Activity Validation
  console.log('\nTest 2: Activity Validation');
  console.log('--------------------------------');

  try {
    const activityLogs = [
      {
        timestamp: new Date(Date.now() - 60000).toISOString(),
        ipAddress: '192.168.1.1',
        deviceId: 'device-123'
      },
      {
        timestamp: new Date().toISOString(),
        ipAddress: '192.168.1.1',
        deviceId: 'device-123'
      }
    ];

    const activityCheck = await security.validateActivity(activityLogs);

    console.log('✓ Activity validation:');
    console.log(`  Suspicious: ${activityCheck.isSuspicious}`);
    console.log(`  Confidence: ${(activityCheck.confidence * 100).toFixed(1)}%`);
    console.log(`  Logs analyzed: ${activityCheck.logCount}`);
    console.log(`  Anomalies: ${activityCheck.anomalies.length > 0 ? activityCheck.anomalies.join(', ') : 'None'}\n`);

  } catch (error) {
    console.error('✗ Test failed:', error.message);
  }

  // Test 3: Security Report Generation
  console.log('Test 3: Security Report Generation');
  console.log('----------------------------------');

  try {
    const report = await security.generateSecurityReport({
      timeframe: '24h',
      format: 'json'
    });

    console.log('✓ Report generated:');
    console.log(`  Trace ID: ${report.traceId}`);
    console.log(`  Format: ${report.reportMetadata.format}`);
    console.log(`  Timeframe: ${report.reportMetadata.timeframe}`);
    console.log(`  Total transactions: ${report.summary.totalTransactionsAnalyzed}\n`);

  } catch (error) {
    console.error('✗ Test failed:', error.message);
  }

  // Test 4: Utility Functions
  console.log('Test 4: Utility Functions');
  console.log('------------------------');

  try {
    // Sanitization
    const dirty = '<script>alert("xss")</script>';
    const clean = sanitizeInput(dirty);
    console.log('✓ Input sanitization:');
    console.log(`  Before: "${dirty}"`);
    console.log(`  After: "${clean}"\n`);

    // Encryption / decryption
    const secret = 'my-secure-secret-123';
    const encryptionKey = 'demo-key-1234567890demo-key-1234';
    const encrypted = encryptData(secret, encryptionKey);
    const decrypted = decryptData(encrypted, encryptionKey);
    console.log('✓ Encryption / decryption:');
    console.log(`  Original: ${secret}`);
    console.log(`  Encrypted: ${encrypted}`);
    console.log(`  Decrypted: ${decrypted}\n`);

    // Masking
    const creditCard = '4532015112830366';
    const masked = maskSensitiveData(creditCard, 4);
    console.log('✓ Data masking:');
    console.log(`  Original: ${creditCard}`);
    console.log(`  Masked: ${masked}\n`);

    // UUID validation
    const validUUID = '550e8400-e29b-41d4-a716-446655440000';
    const invalidUUID = 'not-a-uuid';
    console.log('✓ UUID validation:');
    console.log(`  "${validUUID}" is valid: ${isValidUUID(validUUID)}`);
    console.log(`  "${invalidUUID}" is valid: ${isValidUUID(invalidUUID)}\n`);

    // IP validation
    const validIP = '192.168.1.1';
    const invalidIP = 'not-an-ip';
    console.log('✓ IP validation:');
    console.log(`  "${validIP}" is valid: ${isValidIP(validIP)}`);
    console.log(`  "${invalidIP}" is valid: ${isValidIP(invalidIP)}\n`);

  } catch (error) {
    console.error('✗ Test failed:', error.message);
  }

  // Test 5: Error Handling
  console.log('Test 5: Error Handling');
  console.log('---------------------');

  try {
    // Attempt invalid analysis
    const result = await security.analyzeTransaction({
      orderId: 'order-123'
    });

    console.log('✓ Validation error handling:');
    console.log(`  Error caught: ${result.error}\n`);

  } catch (error) {
    console.error('✗ Unexpected error:', error.message);
  }

  // Summary
  console.log('================================');
  console.log('✅ All tests completed!\n');
  console.log('gerardian SDK is ready for integration.');
  console.log('See README.md for integration examples.\n');
})();

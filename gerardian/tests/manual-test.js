/**
 * Quick Manual Test - Run with: node manual-test.js
 */

const gerardian = require('../src/index');

const security = new gerardian.Engine({
  riskThreshold: 75
});

(async () => {
  console.log('Testing gerardian SDK...\n');

  // Test 1: Normal transaction
  const result1 = await security.analyzeTransaction({
    orderId: 'order-1',
    amount: 50,
    userId: 'user-1'
  });
  console.log('Normal Transaction:', result1.status, `(Risk: ${result1.assessment.riskScore})`);

  // Test 2: Suspicious transaction
  const result2 = await security.analyzeTransaction({
    orderId: 'order-2',
    amount: 2000,
    userId: 'user-1'
  });
  console.log('Suspicious Transaction:', result2.status, `(Risk: ${result2.assessment.riskScore})`);
  console.log('Triggers:', result2.assessment.triggers.join(', '));

  // Test 3: User activity
  const result3 = await security.validateUserActivity([
    { timestamp: new Date().toISOString(), ipAddress: '192.168.1.1', deviceId: 'dev-1' }
  ]);
  console.log('\nUser Activity Check:', result3.isSuspicious ? 'SUSPICIOUS' : 'NORMAL');
})();

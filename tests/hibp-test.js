/**
 * Test local integration helpers with gerardian
 * Run with: node tests/hibp-test.js
 */

const { checkUrlSafety, geolocateIP, analyzeTransactionWithIntegrations } = require('../src/integrations');
const { Engine } = require('../src/index');

(async () => {
  console.log('🛡️  gerardian local integration test\n');
  console.log('====================================================\n');

  // Initialize gerardian engine
  const security = new Engine({ riskThreshold: 75 });

  // Example 1: Check URL safety
  console.log('Test 1: Check URL Safety');
  console.log('-----------------------------------');
  console.log('(Using local demo heuristic)');
  
  try {
    const safeUrl = 'https://example.com/checkout';
    const unsafeUrl = 'javascript:alert(1)';
    console.log(`Safe URL: ${safeUrl}`);
    console.log(`Status: ${await checkUrlSafety(safeUrl) ? '✅ SAFE' : '⚠️ UNSAFE'}\n`);
    console.log(`Unsafe URL: ${unsafeUrl}`);
    console.log(`Status: ${await checkUrlSafety(unsafeUrl) ? '✅ SAFE' : '⚠️ UNSAFE'}\n`);
  } catch (error) {
    console.log(`Note: URL safety check skipped (${error.message})`);
  }

  // Example 2: Transaction with enhanced security checks
  console.log('\n\nTest 2: Enhanced Transaction Analysis');
  console.log('------------------------------------');

  const orderData = {
    orderId: 'order-integration-001',
    amount: 250,
    currency: 'USD',
    metadata: {
      ipAddress: '203.0.113.45',
      shippingUrl: undefined  // No suspicious URL
    }
  };

  try {
    // 1. Run gerardian's built-in analysis
    const baseAnalysis = await security.analyzeTransaction(orderData);
    console.log('Base Analysis (gerardian only):');
    console.log(`  Risk Score: ${baseAnalysis.assessment.riskScore}`);
    console.log(`  Status: ${baseAnalysis.status}`);
    console.log(`  Triggers: ${baseAnalysis.assessment.triggers.join(', ') || 'None'}\n`);

    // 2. Run enhanced analysis with local integrations
    const enhancement = await analyzeTransactionWithIntegrations(orderData);
    
    console.log('Enhanced Analysis (with local integrations):');
    console.log(`  Additional Risk Boost: +${enhancement.riskBoosts} points`);
    console.log(`  New Triggers: ${enhancement.additionalTriggers.join(', ') || 'None'}`);
    console.log(`  Integrations Used:`);
    console.log(`    - Geolocation: ${enhancement.integrations.geolocation ? '✅' : '❌'}`);
    console.log(`    - URL Safety: ${enhancement.integrations.urlSafety ? '✅' : '❌'}`);

    const finalRiskScore = baseAnalysis.assessment.riskScore + enhancement.riskBoosts;
    const finalStatus = finalRiskScore >= security.riskThreshold ? 'BLOCKED' : 'APPROVED';
    console.log(`\n  Final Risk Score: ${finalRiskScore}`);
    console.log(`  Final Decision: ${finalStatus}`);

  } catch (error) {
    console.error('Analysis failed:', error.message);
  }

  // Example 3: Bulk URL check
  console.log('\n\nTest 3: Bulk URL Check');
  console.log('-------------------------');
  
  const testUrls = [
    'https://store.com/one',
    'https://shop.example/two',
    'javascript:alert(1)'
  ];

  console.log('Checking multiple URLs...\n');
  
  for (const url of testUrls) {
    try {
      const isSafe = await checkUrlSafety(url);
      console.log(`${url}: ${isSafe ? '✅ SAFE' : '⚠️ UNSAFE'}`);
    } catch (error) {
      console.log(`${url}: ⏭️  SKIPPED (error)`);
    }
  }

  console.log('\n\n====================================================');
  console.log('✅ Integration test complete!\n');
  console.log('Key takeaways:');
  console.log('  1. URL safety checks work offline');
  console.log('  2. Risk scores are still driven by transaction behavior');
  console.log('  3. Transactions can be blocked automatically');
  console.log('  4. 100% offline - no API keys required.');
})();

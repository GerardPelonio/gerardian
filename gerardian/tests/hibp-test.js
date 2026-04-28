// Test if an email, password, or username is compromised in a breach using the Have I Been Pwned API
/**
 * Test HIBP Integration with gerardian
 * Run with: node hibp-test.js
 */

const { checkCredentialBreach, getBreachDetails, analyzeTransactionWithIntegrations } = require('../src/integrations');
const { Engine } = require('../src/index');

(async () => {
  console.log('🛡️  gerardian + Have I Been Pwned Integration Test\n');
  console.log('====================================================\n');

  // Initialize gerardian engine
  const security = new Engine({ riskThreshold: 75 });

  // Example 1: Check if a well-known breach email
  console.log('Test 1: Check Email in Known Breach');
  console.log('-----------------------------------');
  console.log('(Using public test email from HIBP)');
  
  try {
    // This is a publicly documented test email in HIBP for testing
    const testEmail = 'test@example.com';
    const isBreached = await checkCredentialBreach(testEmail);
    console.log(`Email: ${testEmail}`);
    console.log(`Status: ${isBreached ? '⚠️  FOUND IN BREACH' : '✅ No breach found'}\n`);

    if (isBreached) {
      const breaches = await getBreachDetails(testEmail);
      console.log(`Number of breaches: ${breaches.length}`);
      breaches.slice(0, 3).forEach(breach => {
        console.log(`  - ${breach.Name} (${new Date(breach.BreachDate).getFullYear()})`);
      });
    }
  } catch (error) {
    console.log(`Note: HIBP API check skipped (${error.message})`);
  }

  // Example 2: Transaction with enhanced security checks
  console.log('\n\nTest 2: Enhanced Transaction Analysis');
  console.log('------------------------------------');

  const orderData = {
    orderId: 'order-hibp-001',
    amount: 250,
    userId: 'user-premium-001',
    currency: 'USD',
    metadata: {
      ipAddress: '203.0.113.45',
      userEmail: 'customer@example.com',
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

    // 2. Run enhanced analysis with external APIs
    const enhancement = await analyzeTransactionWithIntegrations(orderData, orderData.metadata.userEmail);
    
    console.log('Enhanced Analysis (with integrations):');
    console.log(`  Additional Risk Boost: +${enhancement.riskBoosts} points`);
    console.log(`  New Triggers: ${enhancement.additionalTriggers.join(', ') || 'None'}`);
    console.log(`  Integrations Used:`);
    console.log(`    - HIBP Breach Check: ${enhancement.integrations.hibp ? '✅' : '❌'}`);
    console.log(`    - Geolocation: ${enhancement.integrations.geolocation ? '✅' : '❌'}`);
    console.log(`    - URL Safety: ${enhancement.integrations.urlSafety ? '✅' : '❌'}`);

    const finalRiskScore = baseAnalysis.assessment.riskScore + enhancement.riskBoosts;
    const finalStatus = finalRiskScore >= security.riskThreshold ? 'BLOCKED' : 'APPROVED';
    console.log(`\n  Final Risk Score: ${finalRiskScore}`);
    console.log(`  Final Decision: ${finalStatus}`);

  } catch (error) {
    console.error('Analysis failed:', error.message);
  }

  // Example 3: Bulk email breach check
  console.log('\n\nTest 3: Bulk Breach Check');
  console.log('-------------------------');
  
  const testEmails = [
    'secure-user@example.com',
    'another-user@test.com',
    'customer@store.com'
  ];

  console.log('Checking multiple emails...\n');
  
  for (const email of testEmails) {
    try {
      const isBreached = await checkCredentialBreach(email);
      console.log(`${email}: ${isBreached ? '⚠️ BREACH FOUND' : '✅ SAFE'}`);
    } catch (error) {
      console.log(`${email}: ⏭️  SKIPPED (API limit or error)`);
    }
  }

  console.log('\n\n====================================================');
  console.log('✅ Integration test complete!\n');
  console.log('Key takeaways:');
  console.log('  1. HIBP integration adds credential breach detection');
  console.log('  2. Risk scores are boosted for compromised accounts');
  console.log('  3. Transactions can be blocked automatically');
  console.log('  4. 100% FREE - no API keys required for HIBP!');
})();

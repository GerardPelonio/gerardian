/**
 * gerardian - Local Security Integrations
 * Offline helpers that avoid external API dependencies
 */

/**
 * Offline breach heuristic
 * Checks for known demo indicators without calling external services
 * 
 * @param {string} email - User email to check
 * @returns {Promise<boolean>} - True if breach found
 */
async function checkCredentialBreach(email) {
  if (typeof email !== 'string' || email.length === 0) {
    return false;
  }

  const normalizedEmail = email.trim().toLowerCase();
  const suspiciousMarkers = ['breach', 'pwned', 'leak', 'compromised'];
  const knownDemoEmails = new Set(['test@example.com', 'pwned@example.com']);

  return knownDemoEmails.has(normalizedEmail) || suspiciousMarkers.some(marker =>
    normalizedEmail.includes(marker)
  );
}

/**
 * Get breach information for an email
 * Returns a local demo list when the heuristic flags the address
 * 
 * @param {string} email - User email
 * @returns {Promise<Array>} - Array of breaches
 */
async function getBreachDetails(email) {
  const isBreached = await checkCredentialBreach(email);

  if (!isBreached) {
    return [];
  }

  return [
    {
      Name: 'Gerardian Demo Breach',
      Title: 'Local breach heuristic',
      BreachDate: '2024-01-01',
      Description: 'Offline demo result returned without calling an external API.'
    }
  ];
}

/**
 * Offline URL safety heuristic
 * Detects obviously unsafe URLs without external services
 * 
 * @param {string} url - URL to check
 * @returns {Promise<boolean>} - True if URL is safe
 */
async function checkUrlSafety(url) {
  if (typeof url !== 'string' || url.trim().length === 0) {
    return true;
  }

  const normalizedUrl = url.trim().toLowerCase();

  if (
    normalizedUrl.startsWith('javascript:') ||
    normalizedUrl.startsWith('data:') ||
    normalizedUrl.includes('localhost') ||
    normalizedUrl.includes('127.0.0.1') ||
    normalizedUrl.includes('0.0.0.0')
  ) {
    return false;
  }

  return true;
}

/**
 * MaxMind GeoIP2 Lite (Free)
 * Lightweight geolocation lookup using free GeoIP2 database
 * 
 * Note: For production, use MaxMind API or download their free GeoLite2 database
 * This is a simplified version
 * 
 * @param {string} ipAddress - IP to geolocate
 * @returns {Promise<Object>} - Geolocation data
 */
async function geolocateIP(ipAddress) {
  try {
    // Using free geoip-lite library (npm install geoip-lite)
    const geoip = require('geoip-lite');
    const result = geoip.lookup(ipAddress);
    
    return {
      ip: ipAddress,
      country: result?.country || 'UNKNOWN',
      region: result?.region || 'UNKNOWN',
      city: result?.city || 'UNKNOWN',
      coordinates: result?.ll || null,
      timezone: result?.timezone || 'UNKNOWN'
    };
  } catch (error) {
    console.error('Geolocation lookup failed:', error.message);
    return null;
  }
}

/**
 * Analyze transaction with local integrations
 * Enhances gerardian's built-in risk scoring without external dependencies
 * 
 * @param {Object} orderData - Transaction data
 * @param {string} userEmail - User email (for breach check)
 * @returns {Promise<Object>} - Enhanced risk assessment
 */
async function analyzeTransactionWithIntegrations(orderData, userEmail) {
  let riskBoosts = 0;
  const additionalTriggers = [];

  try {
    // Check 1: Has user's email been in a breach?
    if (userEmail) {
      const isBreached = await checkCredentialBreach(userEmail);
      if (isBreached) {
        riskBoosts += 40; // Significant risk boost
        additionalTriggers.push('CREDENTIAL_BREACH');
      }
    }
  } catch (error) {
    console.warn('HIBP check failed:', error.message);
  }

  try {
    // Check 2: Is the IP address in a safe location?
    if (orderData.metadata?.ipAddress) {
      const geo = await geolocateIP(orderData.metadata.ipAddress);
      // Store for later use in geolocation checks
      orderData.metadata.geolocation = geo;
    }
  } catch (error) {
    console.warn('Geolocation check failed:', error.message);
  }

  try {
    // Check 3: If order contains a URL, check if it's safe
    if (orderData.metadata?.shippingUrl) {
      const isSafe = await checkUrlSafety(orderData.metadata.shippingUrl);
      if (!isSafe) {
        riskBoosts += 50;
        additionalTriggers.push('MALICIOUS_URL_DETECTED');
      }
    }
  } catch (error) {
    console.warn('URL safety check failed:', error.message);
  }

  return {
    riskBoosts,
    additionalTriggers,
    integrations: {
      hibp: !!userEmail,
      geolocation: !!orderData.metadata?.geolocation,
      urlSafety: !!orderData.metadata?.shippingUrl
    }
  };
}

module.exports = {
  checkCredentialBreach,
  getBreachDetails,
  checkUrlSafety,
  geolocateIP,
  analyzeTransactionWithIntegrations
};

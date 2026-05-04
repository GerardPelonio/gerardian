/**
 * gerardian - Local Security Integrations
 * Offline helpers that avoid external API dependencies
 */

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
 * @returns {Promise<Object>} - Enhanced risk assessment
 */
async function analyzeTransactionWithIntegrations(orderData) {
  let riskBoosts = 0;
  const additionalTriggers = [];

  try {
    // Check 1: Is the IP address in a safe location?
    if (orderData.metadata?.ipAddress) {
      const geo = await geolocateIP(orderData.metadata.ipAddress);
      // Store for later use in geolocation checks
      orderData.metadata.geolocation = geo;
    }
  } catch (error) {
    console.warn('Geolocation check failed:', error.message);
  }

  try {
    // Check 2: If order contains a URL, check if it's safe
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
      geolocation: !!orderData.metadata?.geolocation,
      urlSafety: !!orderData.metadata?.shippingUrl
    }
  };
}

module.exports = {
  checkUrlSafety,
  geolocateIP,
  analyzeTransactionWithIntegrations
};

/**
 * gerardian - External API Integrations
 * Free & powerful third-party integrations for enhanced security
 */

const https = require('https');

/**
 * Have I Been Pwned (HIBP) Integration
 * Check if user's email was in a known data breach
 * 
 * @param {string} email - User email to check
 * @returns {Promise<boolean>} - True if breach found
 */
async function checkCredentialBreach(email) {
  return new Promise((resolve, reject) => {
    const encodedEmail = encodeURIComponent(email);
    const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodedEmail}`;
    
    const options = {
      headers: {
        'User-Agent': 'gerardian-security-sdk/1.0.0',
        'Accept': 'application/json'
      }
    };

    const req = https.get(url, options, (res) => {
      let data = '';

      res.on('data', chunk => {
        data += chunk;
      });

      res.on('end', () => {
        if (res.statusCode === 200) {
          // Email found in breach
          resolve(true);
        } else if (res.statusCode === 404) {
          // Email not found (safe)
          resolve(false);
        } else if (res.statusCode === 401 || res.statusCode === 429) {
          // Unauthorized or rate limited - skip silently (return safe)
          resolve(false);
        } else {
          reject(new Error(`HIBP API error: ${res.statusCode}`));
        }
      });
    }).on('error', reject);
    
    // Add timeout to prevent hanging
    req.setTimeout(5000, () => {
      req.destroy();
      resolve(false);
    });
  });
}

/**
 * Get breach information for an email
 * Returns list of breaches this email was part of
 * 
 * @param {string} email - User email
 * @returns {Promise<Array>} - Array of breaches
 */
async function getBreachDetails(email) {
  return new Promise((resolve, reject) => {
    const encodedEmail = encodeURIComponent(email);
    const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodedEmail}?truncateResponse=false`;
    
    const options = {
      headers: {
        'User-Agent': 'gerardian-security-sdk/1.0.0',
        'Accept': 'application/json'
      }
    };

    https.get(url, options, (res) => {
      let data = '';

      res.on('data', chunk => {
        data += chunk;
      });

      res.on('end', () => {
        if (res.statusCode === 200) {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(new Error('Failed to parse HIBP response'));
          }
        } else if (res.statusCode === 404) {
          resolve([]);
        } else {
          reject(new Error(`HIBP API error: ${res.statusCode}`));
        }
      });
    }).on('error', reject);
  });
}

/**
 * Google Safe Browsing Integration (Free Tier)
 * Detect if URL is malicious/phishing (requires API key but has free tier)
 * 
 * @param {string} url - URL to check
 * @returns {Promise<boolean>} - True if URL is safe
 */
async function checkUrlSafety(url) {
  // Note: This requires a free Google API key from Google Cloud Console
  // For now, returning a placeholder - implement with your API key
  
  try {
    const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
    if (!apiKey) {
      console.warn('Google Safe Browsing API key not configured');
      return true;
    }

    const requestBody = {
      client: {
        clientId: 'gerardian-sdk',
        clientVersion: '1.0.0'
      },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }]
      }
    };

    return new Promise((resolve, reject) => {
      const postData = JSON.stringify(requestBody);
      
      const options = {
        hostname: 'safebrowsing.googleapis.com',
        path: `/v4/threatMatches:find?key=${apiKey}`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': postData.length
        }
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const result = JSON.parse(data);
            // If matches array exists and has items, URL is unsafe
            resolve(!result.matches || result.matches.length === 0);
          } catch (e) {
            reject(e);
          }
        });
      });

      req.on('error', reject);
      req.write(postData);
      req.end();
    });
  } catch (error) {
    console.error('URL safety check failed:', error.message);
    return true; // Fail open - allow if check fails
  }
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
 * Analyze transaction with free external integrations
 * Enhances geraldian's built-in risk scoring
 * 
 * @param {Object} orderData - Transaction data
 * @param {Object} userEmail - User email (for breach check)
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

/**
 * gerardian - Utility Functions
 * Helper functions for data sanitization, encryption, and common operations
 */

const crypto = require('crypto');

/**
 * Sanitize input to prevent injection attacks
 * @param {any} input - Input to sanitize
 * @returns {any} - Sanitized input
 */
function sanitizeInput(input) {
  if (typeof input === 'string') {
    // Remove potentially harmful characters
    return input
      .replace(/[<>\"']/g, '')
      .trim();
  }

  if (typeof input === 'object' && input !== null) {
    const sanitized = Array.isArray(input) ? [] : {};
    for (const [key, value] of Object.entries(input)) {
      sanitized[key] = sanitizeInput(value);
    }
    return sanitized;
  }

  return input;
}

/**
 * Encrypt sensitive data (reversible)
 * @param {string} data - Data to encrypt
 * @param {string} key - Encryption key
 * @returns {string} - Encrypted value with IV
 */
function encryptData(data, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.alloc(32, key), iv);
  
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return `${iv.toString('hex')}:${encrypted}`;
}

/**
 * Decrypt data
 * @param {string} encrypted - Encrypted data (format: iv:encrypted)
 * @param {string} key - Decryption key
 * @returns {string} - Decrypted value
 */
function decryptData(encrypted, key) {
  const [ivHex, encryptedHex] = encrypted.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.alloc(32, key), iv);
  
  let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

/**
 * Mask sensitive information for logging
 * @param {string} value - Value to mask
 * @param {number} visible - Number of characters to show at end
 * @returns {string} - Masked value
 */
function maskSensitiveData(value, visible = 4) {
  if (typeof value !== 'string' || value.length <= visible) {
    return '****';
  }
  return '*'.repeat(value.length - visible) + value.slice(-visible);
}

/**
 * Format currency amount
 * @param {number} amount - Amount
 * @param {string} currency - Currency code
 * @returns {string} - Formatted amount
 */
function formatCurrency(amount, currency = 'USD') {
  const formatter = new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: currency
  });
  return formatter.format(amount);
}

/**
 * Validate UUID format
 * @param {string} uuid - UUID to validate
 * @returns {boolean} - True if valid UUID
 */
function isValidUUID(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

/**
 * Validate IP address format
 * @param {string} ip - IP address to validate
 * @returns {boolean} - True if valid IPv4
 */
function isValidIP(ip) {
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  return ipRegex.test(ip);
}

/**
 * Calculate distance between two geographical points (haversine formula)
 * @param {number} lat1 - First latitude
 * @param {number} lon1 - First longitude
 * @param {number} lat2 - Second latitude
 * @param {number} lon2 - Second longitude
 * @returns {number} - Distance in kilometers
 */
function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371; // Earth radius in km
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

/**
 * Retry logic for async operations
 * @param {Function} fn - Async function to retry
 * @param {number} maxAttempts - Maximum number of attempts
 * @param {number} delayMs - Delay between attempts in milliseconds
 * @returns {Promise} - Result of function
 */
async function retryAsync(fn, maxAttempts = 3, delayMs = 1000) {
  let lastError;
  
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt < maxAttempts) {
        await new Promise(resolve => setTimeout(resolve, delayMs * attempt));
      }
    }
  }
  
  throw lastError;
}

module.exports = {
  sanitizeInput,
  encryptData,
  decryptData,
  maskSensitiveData,
  formatCurrency,
  isValidUUID,
  isValidIP,
  calculateDistance,
  retryAsync
};

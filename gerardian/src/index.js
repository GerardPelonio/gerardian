/**
 * gerardian - Security Middleware & Monitoring SDK
 * Main entry point
 * @version 1.0.0-stable
 */

const { Engine, GerardianValidationError } = require('./engine');
const { sanitizeInput } = require('./utils');
const { validateSchema } = require('./validation');

/**
 * Factory function to initialize gerardian
 * @param {Object} options - Configuration options
 * @returns {Engine} - Initialized security engine
 */
function createSecurityEngine(options = {}) {
  return new Engine(options);
}

module.exports = {
  Engine,
  createSecurityEngine,
  GerardianValidationError,
  sanitizeInput,
  validateSchema,

  // Direct initialization shorthand
  ...new Engine({})
};

// Support both ES6 and CommonJS usage
module.exports.default = createSecurityEngine;

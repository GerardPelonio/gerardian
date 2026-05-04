/**
 * gerardian - Validation Schema Module
 * Defines and validates data contracts across the SDK
 */

/**
 * Transaction Schema Definition
 */
const TRANSACTION_SCHEMA = {
  type: 'object',
  required: ['orderId', 'amount'],
  properties: {
    orderId: { type: 'string', minLength: 1 },
    amount: { type: 'number', minimum: 0 },
    currency: { type: 'string' },
    metadata: { type: 'object' }
  }
};

/**
 * Activity Log Schema Definition
 */
const ACTIVITY_LOG_SCHEMA = {
  type: 'array',
  items: {
    type: 'object',
    required: ['timestamp', 'ipAddress', 'deviceId'],
    properties: {
      timestamp: { type: 'string' },
      ipAddress: { type: 'string', pattern: '^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$' },
      deviceId: { type: 'string' },
      userAgent: { type: 'string' },
      sessionId: { type: 'string' }
    }
  }
};

/**
 * Report Configuration Schema
 */
const REPORT_CONFIG_SCHEMA = {
  type: 'object',
  properties: {
    timeframe: { type: 'string', pattern: '^\\d+[mhd]$' },
    format: { type: 'string', enum: ['json', 'csv'] }
  }
};

/**
 * Output Response Schema (Standardized JSON Contract)
 */
const RESPONSE_SCHEMA = {
  type: 'object',
  required: ['traceId', 'timestamp'],
  properties: {
    traceId: { type: 'string' },
    timestamp: { type: 'string' },
    assessment: {
      type: 'object',
      properties: {
        riskScore: { type: 'number', minimum: 0, maximum: 100 },
        action: { type: 'string', enum: ['BLOCK', 'ALLOW', 'ERROR'] },
        triggers: { type: 'array' }
      }
    }
  }
};

/**
 * Simple JSON Schema validator
 * @param {Object} data - Data to validate
 * @param {Object} schema - Schema definition
 * @returns {Object} - { valid: boolean, errors: Array }
 */
function validateSchema(data, schema) {
  const errors = [];

  if (schema.required) {
    for (const field of schema.required) {
      if (!(field in data)) {
        errors.push(`Missing required field: ${field}`);
      }
    }
  }

  if (schema.properties) {
    for (const [field, fieldSchema] of Object.entries(schema.properties)) {
      if (field in data) {
        const value = data[field];

        if (fieldSchema.type && typeof value !== fieldSchema.type) {
          errors.push(`Field ${field} must be of type ${fieldSchema.type}`);
        }

        if (fieldSchema.minimum !== undefined && value < fieldSchema.minimum) {
          errors.push(`Field ${field} must be >= ${fieldSchema.minimum}`);
        }

        if (fieldSchema.maximum !== undefined && value > fieldSchema.maximum) {
          errors.push(`Field ${field} must be <= ${fieldSchema.maximum}`);
        }

        if (fieldSchema.enum && !fieldSchema.enum.includes(value)) {
          errors.push(`Field ${field} must be one of: ${fieldSchema.enum.join(', ')}`);
        }

        if (fieldSchema.pattern) {
          const regex = new RegExp(fieldSchema.pattern);
          if (!regex.test(value)) {
            errors.push(`Field ${field} does not match required pattern`);
          }
        }
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

module.exports = {
  TRANSACTION_SCHEMA,
  ACTIVITY_LOG_SCHEMA,
  REPORT_CONFIG_SCHEMA,
  RESPONSE_SCHEMA,
  validateSchema
};

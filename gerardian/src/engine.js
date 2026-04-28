/**
 * gerardian Engine
 * Security Middleware & Monitoring SDK for distributed retail and supply chain applications
 * @version 1.0.0-stable
 */

const crypto = require('crypto');
const { sanitizeInput } = require('./utils');

/**
 * Custom error class for validation failures
 */
class GerardianValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'GerardianValidationError';
  }
}

/**
 * Core Security Engine
 * Provides real-time anomaly detection and risk scoring
 */
class Engine {
  constructor(options = {}) {
    this.apiKey = options.apiKey || null;
    this.riskThreshold = options.riskThreshold || 75;
    this.failMode = options.failMode || 'fail-closed'; // 'fail-open' or 'fail-closed'
    
    // Store transaction and activity history for pattern detection
    this.transactionHistory = new Map();
    this.activityHistory = new Map();
    
    // Rate limiting configuration
    this.rateLimitWindow = 60000; // 1 minute in ms
    this.rateLimitMaxRequests = 1000;
    this.requestCounts = new Map();
    
    if (!this.apiKey) {
      console.warn('Warning: gerardian initialized without API key');
    }
  }

  /**
   * Generate a unique trace ID for request tracking
   * @returns {string} Trace ID
   */
  _generateTraceId() {
    return `sec-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`;
  }

  /**
   * Validate transaction input against schema
   * @param {Object} orderData - Transaction data
   * @throws {GerardianValidationError} - If validation fails
   */
  _validateTransactionSchema(orderData) {
    if (!orderData || typeof orderData !== 'object') {
      throw new GerardianValidationError('orderData must be a valid object');
    }

    if (!orderData.orderId || typeof orderData.orderId !== 'string') {
      throw new GerardianValidationError('orderId is required and must be a string');
    }

    if (typeof orderData.amount !== 'number' || orderData.amount <= 0) {
      throw new GerardianValidationError('amount is required and must be a positive number');
    }

    if (!orderData.userId || typeof orderData.userId !== 'string') {
      throw new GerardianValidationError('userId is required and must be a string');
    }

    // Optional fields validation
    if (orderData.currency && typeof orderData.currency !== 'string') {
      throw new GerardianValidationError('currency must be a string');
    }

    if (orderData.metadata && typeof orderData.metadata !== 'object') {
      throw new GerardianValidationError('metadata must be an object');
    }
  }

  /**
   * Calculate risk score based on transaction patterns
   * @param {Object} orderData - Transaction data
   * @returns {Object} - Risk assessment
   */
  _calculateRiskScore(orderData) {
    let riskScore = 0;
    const triggers = [];
    const metadata = orderData.metadata || {};

    // Check for velocity-based attacks (multiple transactions in short time)
    const userHistory = this.transactionHistory.get(orderData.userId) || [];
    const recentTransactions = userHistory.filter(
      t => Date.now() - t.timestamp < 300000 // Last 5 minutes
    );

    if (recentTransactions.length > 5) {
      riskScore += 30;
      triggers.push('VELOCITY_EXCEEDED');
    }

    // Check for unusual amounts
    if (userHistory.length > 0) {
      const avgAmount = userHistory.reduce((sum, t) => sum + t.amount, 0) / userHistory.length;
      if (orderData.amount > avgAmount * 2.5) {
        riskScore += 25;
        triggers.push('AMOUNT_ANOMALY');
      }
    }

    // Deterministic geographical mismatch detection
    if (metadata.ipCountry && metadata.expectedCountry && metadata.ipCountry !== metadata.expectedCountry) {
      riskScore += 20;
      triggers.push('GEO_MISMATCH');
    }

    // Check for suspicious patterns in metadata
    if (metadata.suspiciousIndicators) {
      riskScore += 15;
      triggers.push('SUSPICIOUS_PATTERN');
    }

    return {
      riskScore: Math.min(100, Math.round(riskScore)),
      triggers
    };
  }

  /**
   * Analyze incoming transaction for anomalies
   * @param {Object} orderData - Transaction data (orderId, amount, userId required)
   * @returns {Promise<Object>} - Assessment result
   */
  async analyzeTransaction(orderData) {
    const traceId = this._generateTraceId();
    const timestamp = new Date().toISOString();
    const safeOrderData = sanitizeInput(orderData);

    try {
      // Rate limiting check
      this._checkRateLimit('transaction');

      // Validate input schema
      this._validateTransactionSchema(safeOrderData);

      // Calculate risk score
      const { riskScore, triggers } = this._calculateRiskScore(safeOrderData);

      // Determine action based on risk score
      const action = riskScore >= this.riskThreshold ? 'BLOCK' : 'ALLOW';
      const status = action === 'BLOCK' ? 'blocked' : 'approved';

      // Update transaction history
      if (!this.transactionHistory.has(safeOrderData.userId)) {
        this.transactionHistory.set(safeOrderData.userId, []);
      }
      this.transactionHistory.get(safeOrderData.userId).push({
        orderId: safeOrderData.orderId,
        amount: safeOrderData.amount,
        timestamp: Date.now()
      });

      // Keep history manageable (last 100 transactions per user)
      const history = this.transactionHistory.get(safeOrderData.userId);
      if (history.length > 100) {
        history.shift();
      }

      return {
        traceId,
        timestamp,
        assessment: {
          riskScore,
          action,
          triggers
        },
        status,
        flags: triggers,
        orderId: safeOrderData.orderId,
        message: action === 'BLOCK' ? 'Transaction flagged as high risk' : 'Transaction approved'
      };
    } catch (error) {
      if (error instanceof GerardianValidationError) {
        return {
          traceId,
          timestamp,
          error: error.message,
          status: 'error',
          assessment: { riskScore: 0, action: 'ERROR', triggers: [] }
        };
      }

      // Engine failure - respect fail mode
      return {
        traceId,
        timestamp,
        error: 'Engine processing error',
        status: this.failMode === 'fail-open' ? 'approved' : 'blocked',
        assessment: { riskScore: 0, action: 'ERROR', triggers: [] }
      };
    }
  }

  /**
   * Validate activity logs for suspicious user behavior
   * @param {Array<Object>} logs - Array of activity logs (timestamp, ipAddress, deviceId)
   * @returns {Promise<Object>} - Validation result
   */
  async validateUserActivity(logs) {
    const traceId = this._generateTraceId();
    const timestamp = new Date().toISOString();
    const safeLogs = sanitizeInput(logs);

    try {
      // Rate limiting check
      this._checkRateLimit('activity');

      if (!Array.isArray(safeLogs) || safeLogs.length === 0) {
        throw new GerardianValidationError('logs must be a non-empty array');
      }

      let suspiciousCount = 0;
      const anomalies = [];

      for (const log of safeLogs) {
        if (!log.timestamp || !log.ipAddress || !log.deviceId) {
          throw new GerardianValidationError(
            'Each log entry must contain timestamp, ipAddress, and deviceId'
          );
        }

        // Check for impossible travel (rapid location changes)
        const logTime = new Date(log.timestamp).getTime();
        const windowStart = logTime - 3600000; // 1 hour window

        const previousLogs = this.activityHistory.get(log.ipAddress) || [];
        const recentActivity = previousLogs.filter(
          l => new Date(l.timestamp).getTime() > windowStart
        );

        if (recentActivity.length > 0 && recentActivity[0].deviceId !== log.deviceId) {
          suspiciousCount++;
          anomalies.push('DEVICE_MISMATCH');
        }

        // Check for brute-force patterns (>10 login attempts per minute)
        const minuteAgo = logTime - 60000;
        const attemptCount = previousLogs.filter(
          l => new Date(l.timestamp).getTime() > minuteAgo
        ).length;

        if (attemptCount > 10) {
          suspiciousCount++;
          anomalies.push('BRUTE_FORCE_ATTEMPT');
        }
      }

      // Store activity history
      const firstLog = logs[0];
      if (!this.activityHistory.has(firstLog.ipAddress)) {
        this.activityHistory.set(firstLog.ipAddress, []);
      }
      this.activityHistory.get(firstLog.ipAddress).push(...logs);

      // Keep history manageable
      const history = this.activityHistory.get(firstLog.ipAddress);
      if (history.length > 500) {
        history.splice(0, history.length - 500);
      }

      const isSuspicious = suspiciousCount > 0;
      const confidence = Math.min(1.0, suspiciousCount / safeLogs.length);

      return {
        traceId,
        timestamp,
        isSuspicious,
        confidence: Math.round(confidence * 100) / 100,
        anomalies,
        logCount: safeLogs.length,
        message: isSuspicious ? 'Suspicious activity detected' : 'Activity appears normal'
      };
    } catch (error) {
      if (error instanceof GerardianValidationError) {
        return {
          traceId,
          timestamp,
          error: error.message,
          isSuspicious: false,
          confidence: 0
        };
      }

      return {
        traceId,
        timestamp,
        error: 'Engine processing error',
        isSuspicious: false,
        confidence: 0
      };
    }
  }

  /**
   * Generate security report for administrative review
   * @param {Object} config - Report configuration (timeframe, format)
   * @returns {Promise<Object|string>} - Structured dataset
   */
  async generateSecurityReport(config = {}) {
    const traceId = this._generateTraceId();
    const timestamp = new Date().toISOString();
    const format = config.format || 'json'; // 'json' or 'csv'
    const timeframeMs = this._parseTimeframe(config.timeframe || '24h');

    try {
      const reportData = {
        traceId,
        timestamp,
        reportMetadata: {
          format,
          timeframe: config.timeframe || '24h',
          generatedAt: timestamp
        },
        summary: {
          totalTransactionsAnalyzed: 0,
          totalBlocked: 0,
          totalApproved: 0,
          commonTriggers: {}
        },
        threats: []
      };

      // Compile historical data (simplified for demo)
      let blockedCount = 0;
      let approvedCount = 0;
      const triggerFrequency = {};

      this.transactionHistory.forEach((userTransactions) => {
        const recentTransactions = userTransactions.filter(
          t => Date.now() - t.timestamp < timeframeMs
        );
        reportData.summary.totalTransactionsAnalyzed += recentTransactions.length;
      });

      reportData.summary.totalBlocked = blockedCount;
      reportData.summary.totalApproved = approvedCount;
      reportData.summary.commonTriggers = triggerFrequency;

      if (format === 'csv') {
        return this._convertReportToCsv(reportData);
      }

      return reportData;
    } catch (error) {
      return {
        traceId,
        timestamp,
        error: error.message,
        summary: { totalTransactionsAnalyzed: 0 }
      };
    }
  }

  /**
   * Parse timeframe string to milliseconds
   * @param {string} timeframe - Format: '5m', '1h', '24h', '7d'
   * @returns {number} - Milliseconds
   */
  _parseTimeframe(timeframe) {
    const units = {
      m: 60000,
      h: 3600000,
      d: 86400000
    };

    const match = timeframe.match(/^(\d+)([mhd])$/);
    if (!match) return 86400000; // Default to 24h

    return parseInt(match[1]) * units[match[2]];
  }

  /**
   * Convert report to CSV format
   * @param {Object} reportData - Report data
   * @returns {string} - CSV formatted string
   */
  _convertReportToCsv(reportData) {
    const headers = ['Metric', 'Value'];
    const rows = [
      headers.join(','),
      `Total Transactions,${reportData.summary.totalTransactionsAnalyzed}`,
      `Total Blocked,${reportData.summary.totalBlocked}`,
      `Total Approved,${reportData.summary.totalApproved}`,
      `Generated At,${reportData.timestamp}`
    ];
    return rows.join('\n');
  }

  /**
   * Check rate limiting
   * @param {string} endpoint - Endpoint identifier
   * @throws {Error} - If rate limit exceeded
   */
  _checkRateLimit(endpoint) {
    const now = Date.now();
    const key = endpoint;

    if (!this.requestCounts.has(key)) {
      this.requestCounts.set(key, []);
    }

    const timestamps = this.requestCounts.get(key);
    
    // Remove old timestamps outside the window
    const recentTimestamps = timestamps.filter(t => now - t < this.rateLimitWindow);
    
    if (recentTimestamps.length >= this.rateLimitMaxRequests) {
      throw new Error(`Rate limit exceeded for ${endpoint}`);
    }

    recentTimestamps.push(now);
    this.requestCounts.set(key, recentTimestamps);
  }
}

module.exports = {
  Engine,
  GerardianValidationError
};

/**
 * Gerardian Engine
 * Security Middleware & Monitoring SDK for distributed retail and supply chain applications
 * @version 1.0.0-stable
 */

const crypto = require('crypto');

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
    this.riskThreshold = options.riskThreshold || 75;
    this.failMode = options.failMode || 'fail-closed'; // 'fail-open' or 'fail-closed'
    
    // Store transaction and activity history for pattern detection
    this.transactionHistory = new Map();
    this.activityHistory = new Map();
    
    // Rate limiting configuration
    this.rateLimitWindow = 60000; // 1 minute in ms
    this.rateLimitMaxRequests = 1000;
    this.requestCounts = new Map();
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

    // Check for velocity-based attacks (multiple transactions in short time)
    const allTransactions = Array.from(this.transactionHistory.values()).flat();
    const recentTransactions = allTransactions.filter(
      t => Date.now() - t.timestamp < 300000 // Last 5 minutes
    );

    if (recentTransactions.length > 5) {
      riskScore += 30;
      triggers.push('VELOCITY_EXCEEDED');
    }

    // Check for unusual amounts
    if (allTransactions.length > 0) {
      const avgAmount = allTransactions.reduce((sum, t) => sum + t.amount, 0) / allTransactions.length;
      if (orderData.amount > avgAmount * 2.5) {
        riskScore += 25;
        triggers.push('AMOUNT_ANOMALY');
      }
    }

    // Simulate geographical mismatch detection
    if (orderData.metadata && orderData.metadata.ipCountry) {
      // In a real implementation, compare with user's previous locations
      // This is a placeholder for geo-mismatch detection
      const isGeoMismatch = Math.random() > 0.85; // 15% chance for demo
      if (isGeoMismatch) {
        riskScore += 20;
        triggers.push('GEO_MISMATCH');
      }
    }

    // Check for suspicious patterns in metadata
    if (orderData.metadata && orderData.metadata.suspiciousIndicators) {
      riskScore += 15;
      triggers.push('SUSPICIOUS_PATTERN');
    }

    // Impossible Travel Detection
    if (orderData.metadata && orderData.metadata.lat && orderData.metadata.lon && allTransactions.length > 0) {
      const lastTx = allTransactions[allTransactions.length - 1];
      if (lastTx.lat && lastTx.lon) {
        const distance = this._calculateDistance(
          lastTx.lat, lastTx.lon,
          orderData.metadata.lat, orderData.metadata.lon
        );
        
        const timeDiffHours = (Date.now() - lastTx.timestamp) / 3600000;
        
        // If speed > 900 km/h (average commercial flight speed), flag it
        if (timeDiffHours > 0 && (distance / timeDiffHours) > 900) {
          riskScore += 40;
          triggers.push('IMPOSSIBLE_TRAVEL');
        }
      }
    }

    // Random baseline noise (represents unknown factors)
    riskScore += Math.random() * 10;

    return {
      riskScore: Math.min(100, Math.round(riskScore)),
      triggers
    };
  }

  /**
   * Calculate distance between two points using Haversine formula
   * @param {number} lat1 - Latitude of first point
   * @param {number} lon1 - Longitude of first point
   * @param {number} lat2 - Latitude of second point
   * @param {number} lon2 - Longitude of second point
   * @returns {number} - Distance in km
   */
  _calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371; // Earth's radius in km
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
      Math.sin(dLon / 2) * Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
  }

  /**
   * Analyze incoming transaction for anomalies
   * @param {Object} orderData - Transaction data (orderId and amount required)
   * @returns {Promise<Object>} - Assessment result
   */
  async analyzeTransaction(orderData) {
    const traceId = this._generateTraceId();
    const timestamp = new Date().toISOString();

    try {
      // Rate limiting check
      this._checkRateLimit('transaction');

      // Validate input schema
      this._validateTransactionSchema(orderData);

      // Calculate risk score
      const { riskScore, triggers } = this._calculateRiskScore(orderData);

      // Determine action based on risk score
      const action = riskScore >= this.riskThreshold ? 'BLOCK' : 'ALLOW';
      const status = action === 'BLOCK' ? 'blocked' : 'approved';

      // Update transaction history
      if (!this.transactionHistory.has('orders')) {
        this.transactionHistory.set('orders', []);
      }
      this.transactionHistory.get('orders').push({
        orderId: orderData.orderId,
        amount: orderData.amount,
        timestamp: Date.now(),
        riskScore,
        triggers,
        lat: orderData.metadata?.lat,
        lon: orderData.metadata?.lon
      });

      // Keep history manageable (last 100 transactions)
      const history = this.transactionHistory.get('orders');
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
        orderId: orderData.orderId,
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
   * This method implements two primary security heuristics:
   * 1. Device Fingerprinting: Detects if multiple devices are using the same IP in a short window.
   * 2. Brute Force Protection: Detects high-frequency activity from a single network source.
   * 
   * @param {Array<Object>} logs - Array of activity logs (timestamp, ipAddress, deviceId)
   * @returns {Promise<Object>} - Validation result with suspicion score
   */
  async validateActivity(logs) {
    const traceId = this._generateTraceId();
    const timestamp = new Date().toISOString();

    try {
      this._checkRateLimit('activity');
      this._validateActivityInput(logs);

      let suspiciousCount = 0;
      const anomalies = new Set();

      for (const log of logs) {
        const previousLogs = this.activityHistory.get(log.ipAddress) || [];

        /**
         * Principle: Device Mismatch Detection
         * If the same IP address is associated with a different deviceId within 1 hour,
         * it may indicate session hijacking or unauthorized account sharing.
         */
        if (this._detectDeviceMismatch(log, previousLogs)) {
          suspiciousCount++;
          anomalies.add('DEVICE_MISMATCH');
        }

        /**
         * Principle: Brute Force Detection
         * If an IP address generates more than 10 activity logs in a single minute,
         * it is flagged as a potential automated attack or credential stuffing attempt.
         */
        if (this._detectBruteForce(log, previousLogs)) {
          suspiciousCount++;
          anomalies.add('BRUTE_FORCE_ATTEMPT');
        }
      }

      this._updateActivityHistory(logs[0].ipAddress, logs);

      const isSuspicious = suspiciousCount > 0;
      const confidence = Math.min(1.0, suspiciousCount / logs.length);

      return {
        traceId,
        timestamp,
        isSuspicious,
        confidence: Math.round(confidence * 100) / 100,
        anomalies: Array.from(anomalies),
        logCount: logs.length,
        message: isSuspicious ? 'Suspicious activity detected' : 'Activity appears normal'
      };
    } catch (error) {
      return this._handleActivityError(error, traceId, timestamp);
    }
  }

  /**
   * Internal helper to validate activity input format
   */
  _validateActivityInput(logs) {
    if (!Array.isArray(logs) || logs.length === 0) {
      throw new GerardianValidationError('logs must be a non-empty array');
    }
    for (const log of logs) {
      if (!log.timestamp || !log.ipAddress || !log.deviceId) {
        throw new GerardianValidationError('Each log entry must contain timestamp, ipAddress, and deviceId');
      }
    }
  }

  /**
   * Internal helper to detect if a device mismatch has occurred on the same IP
   */
  _detectDeviceMismatch(currentLog, history) {
    const oneHourAgo = new Date(currentLog.timestamp).getTime() - 3600000;
    const recentLogs = history.filter(l => new Date(l.timestamp).getTime() > oneHourAgo);
    
    return recentLogs.length > 0 && recentLogs[0].deviceId !== currentLog.deviceId;
  }

  /**
   * Internal helper to detect brute force patterns (high frequency from same IP)
   */
  _detectBruteForce(currentLog, history) {
    const oneMinuteAgo = new Date(currentLog.timestamp).getTime() - 60000;
    const attemptCount = history.filter(l => new Date(l.timestamp).getTime() > oneMinuteAgo).length;
    
    return attemptCount > 10;
  }

  /**
   * Internal helper to update and prune activity history
   */
  _updateActivityHistory(ipAddress, newLogs) {
    if (!this.activityHistory.has(ipAddress)) {
      this.activityHistory.set(ipAddress, []);
    }
    
    const history = this.activityHistory.get(ipAddress);
    history.push(...newLogs);

    if (history.length > 500) {
      history.splice(0, history.length - 500);
    }
  }

  /**
   * Internal helper to handle activity validation errors
   */
  _handleActivityError(error, traceId, timestamp) {
    const baseResponse = { traceId, timestamp, isSuspicious: false, confidence: 0 };
    if (error instanceof GerardianValidationError) {
      return { ...baseResponse, error: error.message };
    }
    return { ...baseResponse, error: 'Engine processing error' };
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

      // Compile historical data
      this.transactionHistory.forEach((userTransactions) => {
        const recentTransactions = userTransactions.filter(
          t => Date.now() - t.timestamp < timeframeMs
        );
        
        reportData.summary.totalTransactionsAnalyzed += recentTransactions.length;
        
        recentTransactions.forEach(t => {
          if (t.riskScore >= this.riskThreshold) {
            reportData.summary.totalBlocked++;
          } else {
            reportData.summary.totalApproved++;
          }
          
          if (t.triggers) {
            t.triggers.forEach(trigger => {
              reportData.summary.commonTriggers[trigger] = (reportData.summary.commonTriggers[trigger] || 0) + 1;
            });
          }
        });
      });

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

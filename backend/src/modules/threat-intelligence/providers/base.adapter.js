// backend/src/modules/threat-intelligence/providers/base.adapter.js
// Base interface and abstract contract for Threat Intelligence provider adapters.

export class BaseThreatProvider {
  /**
   * @param {string} name - Unique provider identifier (e.g., 'ABUSEIPDB', 'VIRUSTOTAL')
   * @param {string[]} supportedTypes - Array of supported IocType strings (e.g. ['IP'])
   * @param {string} envKeyName - Environment variable name containing the API key
   * @param {number} [timeoutMs=5000] - Request timeout in milliseconds
   */
  constructor(name, supportedTypes, envKeyName, timeoutMs = 5000) {
    this.name = name;
    this.supportedTypes = supportedTypes;
    this.envKeyName = envKeyName;
    this.timeoutMs = timeoutMs;
  }

  /**
   * Checks if the required API key or configuration is available in environment.
   * @returns {boolean}
   */
  isConfigured() {
    const key = process.env[this.envKeyName];
    return typeof key === 'string' && key.trim().length > 0 && !key.includes('replace_with');
  }

  /**
   * Returns whether this provider supports the given IOC type.
   * @param {string} type - 'IP' | 'DOMAIN' | 'HASH' | 'URL'
   * @returns {boolean}
   */
  supports(type) {
    return this.supportedTypes.includes(type);
  }

  /**
   * Abstract lookup method to be overridden by concrete provider adapters.
   * @param {string} type - 'IP' | 'DOMAIN' | 'HASH' | 'URL'
   * @param {string} value - Normalized indicator value
   * @returns {Promise<{
   *   status: 'SUCCESS' | 'NOT_FOUND' | 'RATE_LIMITED' | 'ERROR' | 'NOT_CONFIGURED',
   *   verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' | 'UNKNOWN' | null,
   *   score: number | null,
   *   detectionCount: number | null,
   *   totalEngines: number | null,
   *   rawSummary: object | null,
   *   errorMessage: string | null
   * }>}
   */
  async lookup(_type, _value) {
    throw new Error(`lookup() must be implemented by subclass ${this.constructor.name}`);
  }

  /**
   * Helper to perform a bounded HTTP GET with timeout.
   */
  async fetchWithTimeout(url, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
      });
      return response;
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Generates a standardized 'NOT_CONFIGURED' result.
   */
  getNotConfiguredResult() {
    return {
      status: 'NOT_CONFIGURED',
      verdict: null,
      score: null,
      detectionCount: null,
      totalEngines: null,
      rawSummary: null,
      errorMessage: `Provider "${this.name}" is not configured (missing ${this.envKeyName} in environment)`,
    };
  }
}

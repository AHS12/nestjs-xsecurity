import { XSecurityConfig } from '../interfaces/config.interface';

export class ConfigValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigValidationError';
  }
}

export function validateConfig(config: XSecurityConfig): void {
  // Validate Rate Limit Configuration
  if (config.rateLimit) {
    const { enabled, maxAttempts, decayMinutes, cleanupInterval, storeLimit } = config.rateLimit;

    if (enabled !== undefined) {
      if (typeof enabled !== 'boolean') {
        throw new ConfigValidationError('XSecurityConfig: rateLimit.enabled must be a boolean');
      }
    }

    if (maxAttempts !== undefined) {
      if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
        throw new ConfigValidationError(
          'XSecurityConfig:rateLimit.maxAttempts must be a positive integer',
        );
      }
    }

    if (decayMinutes !== undefined) {
      if (!Number.isInteger(decayMinutes) || decayMinutes < 1) {
        throw new ConfigValidationError(
          'XSecurityConfig: rateLimit.decayMinutes must be a positive integer',
        );
      }
    }

    if (cleanupInterval !== undefined) {
      if (!Number.isInteger(cleanupInterval) || cleanupInterval < 1) {
        throw new ConfigValidationError(
          'XSecurityConfig: rateLimit.cleanupInterval must be a positive integer',
        );
      }
    }

    if (storeLimit !== undefined) {
      if (!Number.isInteger(storeLimit) || storeLimit < 1) {
        throw new ConfigValidationError(
          'XSecurityConfig: rateLimit.storeLimit must be a positive integer',
        );
      }
    }
  }

  // Validate Token Configuration
  if (config.token) {
    const { expirySeconds, headerName } = config.token;

    if (expirySeconds !== undefined) {
      if (!Number.isInteger(expirySeconds) || expirySeconds < 1) {
        throw new ConfigValidationError(
          'XSecurityConfig: token.expirySeconds must be a positive integer',
        );
      }
    }

    if (headerName !== undefined) {
      if (typeof headerName !== 'string' || !headerName.trim()) {
        throw new ConfigValidationError(
          'XSecurityConfig: token.headerName must be a non-empty string',
        );
      }

      // Check for valid HTTP header name format
      if (!/^[A-Za-z0-9-]+$/.test(headerName)) {
        throw new ConfigValidationError(
          'XSecurityConfig: token.headerName must contain only alphanumeric characters and hyphens',
        );
      }
    }
  }

  // Validate Secret
  if (config.secret) {
    if (typeof config.secret !== 'string' || !config.secret.trim()) {
      throw new ConfigValidationError('XSecurityConfig:secret must be a non-empty string');
    }
  }

  // Validate Exclude
  if (config.exclude) {
    if (!Array.isArray(config.exclude)) {
      throw new ConfigValidationError('XSecurityConfig: exclude must be an array');
    }
  }

  // Validate Environment Configuration
  if (config.environment) {
    const { enabled, secret } = config.environment;

    if (enabled !== undefined) {
      if (typeof enabled !== 'string' || !enabled.trim()) {
        throw new ConfigValidationError(
          'XSecurityConfig: environment.enabled must be a non-empty string',
        );
      }
    }

    if (secret !== undefined) {
      if (typeof secret !== 'string' || !secret.trim()) {
        throw new ConfigValidationError(
          'XSecurityConfig: environment.secret must be a non-empty string',
        );
      }
    }
  }

  // Validate Error Messages
  if (config.errorMessages) {
    const { rateLimitExceeded, invalidToken } = config.errorMessages;

    if (rateLimitExceeded !== undefined) {
      if (typeof rateLimitExceeded !== 'string' || !rateLimitExceeded.trim()) {
        throw new ConfigValidationError(
          'XSecurityConfig: errorMessages.rateLimitExceeded must be a non-empty string',
        );
      }
    }

    if (invalidToken !== undefined) {
      if (typeof invalidToken !== 'string' || !invalidToken.trim()) {
        throw new ConfigValidationError(
          'XSecurityConfig: errorMessages.invalidToken must be a non-empty string',
        );
      }
    }
  }

  // Validate enabled flag
  if (config.enabled !== undefined && typeof config.enabled !== 'boolean') {
    throw new ConfigValidationError('XSecurityConfig: enabled must be a boolean');
  }
}

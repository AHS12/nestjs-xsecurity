import { XSecurityConfig } from "../interfaces/config.interface";

export class ConfigValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigValidationError";
  }
}

export function validateConfig(config: XSecurityConfig): void {
  // Validate Rate Limit Configuration
  if (config.rateLimit) {
    const { maxAttempts, decayMinutes, cleanupInterval } = config.rateLimit;

    if (maxAttempts !== undefined) {
      if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
        throw new ConfigValidationError(
          "rateLimit.maxAttempts must be a positive integer"
        );
      }
    }

    if (decayMinutes !== undefined) {
      if (!Number.isInteger(decayMinutes) || decayMinutes < 1) {
        throw new ConfigValidationError(
          "rateLimit.decayMinutes must be a positive integer"
        );
      }
    }

    if (cleanupInterval !== undefined) {
      if (!Number.isInteger(cleanupInterval) || cleanupInterval < 1) {
        throw new ConfigValidationError(
          "rateLimit.cleanupInterval must be a positive integer"
        );
      }
    }
  }

  // Validate Token Configuration
  if (config.token) {
    const { secretLength, expirySeconds, headerName } = config.token;

    if (secretLength !== undefined) {
      if (!Number.isInteger(secretLength) || secretLength < 16) {
        throw new ConfigValidationError(
          "token.secretLength must be an integer >= 16"
        );
      }
    }

    if (expirySeconds !== undefined) {
      if (!Number.isInteger(expirySeconds) || expirySeconds < 1) {
        throw new ConfigValidationError(
          "token.expirySeconds must be a positive integer"
        );
      }
    }

    if (headerName !== undefined) {
      if (typeof headerName !== "string" || !headerName.trim()) {
        throw new ConfigValidationError(
          "token.headerName must be a non-empty string"
        );
      }

      // Check for valid HTTP header name format
      if (!/^[A-Za-z0-9-]+$/.test(headerName)) {
        throw new ConfigValidationError(
          "token.headerName must contain only alphanumeric characters and hyphens"
        );
      }
    }
  }

  // Validate Environment Configuration
  if (config.environment) {
    const { enabled, secret } = config.environment;

    if (enabled !== undefined) {
      if (typeof enabled !== "string" || !enabled.trim()) {
        throw new ConfigValidationError(
          "environment.enabled must be a non-empty string"
        );
      }
    }

    if (secret !== undefined) {
      if (typeof secret !== "string" || !secret.trim()) {
        throw new ConfigValidationError(
          "environment.secret must be a non-empty string"
        );
      }
    }
  }

  // Validate Error Messages
  if (config.errorMessages) {
    const { rateLimitExceeded, invalidToken } = config.errorMessages;

    if (rateLimitExceeded !== undefined) {
      if (typeof rateLimitExceeded !== "string" || !rateLimitExceeded.trim()) {
        throw new ConfigValidationError(
          "errorMessages.rateLimitExceeded must be a non-empty string"
        );
      }
    }

    if (invalidToken !== undefined) {
      if (typeof invalidToken !== "string" || !invalidToken.trim()) {
        throw new ConfigValidationError(
          "errorMessages.invalidToken must be a non-empty string"
        );
      }
    }
  }

  // Validate enabled flag
  if (config.enabled !== undefined && typeof config.enabled !== "boolean") {
    throw new ConfigValidationError("enabled must be a boolean");
  }
}

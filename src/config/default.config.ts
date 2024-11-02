import { XSecurityConfig } from '../interfaces/config.interface';

export const DEFAULT_CONFIG: XSecurityConfig = {
  enabled: true,
  rateLimit: {
    enabled: true,
    maxAttempts: 5,
    decayMinutes: 1,
    cleanupInterval: 5,
    storeLimit: 10000,
  },
  token: {
    headerName: 'X-SECURITY-TOKEN',
    expirySeconds: 10, // 10 seconds
  },
  environment: {
    enabled: 'XSECURITY_ENABLED',
    secret: 'XSECURITY_SECRET',
  },
  exclude: [],
  errorMessages: {
    rateLimitExceeded: 'Too many requests. Please try again later.',
    invalidToken: 'Invalid XSECURITY token',
  },
};

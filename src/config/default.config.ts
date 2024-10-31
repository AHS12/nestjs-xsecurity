import { XSecurityConfig } from '../interfaces/config.interface';

export const DEFAULT_CONFIG: XSecurityConfig = {
  enabled: true,
  rateLimit: {
    maxAttempts: 5,
    decayMinutes: 1,
    cleanupInterval: 5,
  },
  token: {
    headerName: 'X-SECURITY-TOKEN',
    secretLength: 32,
    expirySeconds: 10, // 10 seconds
  },
  environment: {
    enabled: 'XSECURITY_ENABLED',
    secret: 'XSECURITY_SECRET',
  },
  errorMessages: {
    rateLimitExceeded: 'Too many requests. Please try again later.',
    invalidToken: 'Invalid XSECURITY token',
  },
};

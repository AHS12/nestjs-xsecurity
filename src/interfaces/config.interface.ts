export interface RateLimitConfig {
  /**
   * Enable/disable the Rate Limiting
   * @default true
   */
  enabled?: boolean;
  /**
   * Maximum number of failed attempts before rate limiting
   * @default 5
   */
  maxAttempts?: number;

  /**
   * Time in minutes before rate limit reset
   * @default 1
   */
  decayMinutes?: number;

  /**
   * Cleanup interval in minutes for rate limit store(when someone do too many requests, rate limit store stores the rate limit info. this cleanup the store)
   * @default 5
   */
  cleanupInterval?: number;

  /**
   * Maximum number of entries in rate limit store
   * @default 10000
   */
  storeLimit?: number;
}

export interface TokenConfig {
  /**
   * Name of the header to look for the security token
   * @default 'X-SECURITY-TOKEN'
   */
  headerName?: string;

  /**
   * Token expiry time in seconds(Token is short lived, so 10 seconds is more than enough)
   * @default 10 (10 seconds)
   */
  expirySeconds?: number;
}

export interface EnvironmentConfig {
  /**
   * Environment variable name for enabling/disabling the middleware
   * @default 'XSECURITY_ENABLED'
   */
  enabled?: string;

  /**
   * Environment variable name for the security secret
   * @default 'XSECURITY_SECRET'
   */
  secret?: string;
}

export interface XSecurityConfig {
  /**
   * Enable/disable the middleware
   * @default true
   */
  enabled?: boolean;

  /**
   * Rate limiting configuration
   */
  rateLimit?: RateLimitConfig;

  /**
   * Token configuration
   */
  token?: TokenConfig;

  /**
   * Environment variable names configuration
   */
  environment?: EnvironmentConfig;

  /**
   * Secret key for token signing. If not provided, will try to use environment variable
   */
  secret?: string;

  /**
   * Routes to exclude from XSecurity middleware
   * Supports string paths and RegExp patterns
   * Example: ['/health', '/public/*', /^\/public\/.*$/]
   */
  exclude?: Array<string | RegExp>;

  /**
   * Custom error messages
   */
  errorMessages?: {
    rateLimitExceeded?: string;
    invalidToken?: string;
  };
}

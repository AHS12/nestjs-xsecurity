import { HttpStatus, Inject, Injectable, NestMiddleware, OnModuleDestroy } from '@nestjs/common';
import * as crypto from 'crypto';
import { NextFunction, Request, Response } from 'express';
import * as os from 'os';
import { XSecurityConfig } from '../interfaces/config.interface';
import { mergeConfig } from '../utils/config.utils';
import { XSECURITY_CONFIG } from '../x-security.module';

interface RateLimitInfo {
  count: number;
  resetTime: number;
}

interface MetricsInfo {
  totalRequests: number;
  blockedRequests: number;
  currentStoreSize: number;
  peakStoreSize: number;
  lastCleanupTime: number;
}
const LOCALHOST_IP: string = '127.0.0.1';
const MAX_STORE_DEFAULT_SIZE: number = 10000;
@Injectable()
export class XSecurityMiddleware implements NestMiddleware, OnModuleDestroy {
  private readonly rateLimitStore = new Map<string, RateLimitInfo>();
  private readonly MAX_STORE_SIZE: number = MAX_STORE_DEFAULT_SIZE;
  private readonly cleanupInterval: NodeJS.Timeout;
  private readonly secret: string;
  private readonly excludePatterns: Array<string | RegExp>;
  private readonly metrics: MetricsInfo = {
    totalRequests: 0,
    blockedRequests: 0,
    currentStoreSize: 0,
    peakStoreSize: 0,
    lastCleanupTime: Date.now(),
  };
  private readonly FORCE_CLEANUP_MEMORY_THRESHOLD: number = 80;
  private readonly MAX_STORE_SIZE_PERCENTAGE: number = 0.8;
  private readonly MAX_STORE_SIZE_CLEANUP_THRESHOLD: number = 0.7;
  private readonly TIME_WINDOW_TRIGGER_THRESHOLD: number = 0.3;

  constructor(@Inject(XSECURITY_CONFIG) private config: XSecurityConfig) {
    this.config = mergeConfig(config);

    this.secret =
      config.secret || process.env[this.config.environment?.secret || 'XSECURITY_SECRET'] || '';

    if (!this.secret) {
      console.warn(
        'XSecurity Warning: No security secret provided. Please provide a secret through config or environment variable.',
      );
    }
    this.MAX_STORE_SIZE = this.config.rateLimit?.storeLimit || MAX_STORE_DEFAULT_SIZE;
    this.excludePatterns = config.exclude || [];

    const cleanupMinutes = this.config.rateLimit?.cleanupInterval || 5;

    this.cleanupInterval = setInterval(
      () => {
        this.checkAndCleanup();
      },
      cleanupMinutes * 60 * 1000,
    );
  }

  use(req: Request, res: Response, next: NextFunction): void {
    try {
      // Check if disabled through environment variable
      const envEnabled = process.env[this.config.environment?.enabled || 'XSECURITY_ENABLED'];
      if (
        this.config.enabled === false ||
        envEnabled === 'false' ||
        this.isExcludedPath(req.originalUrl || req.url)
      ) {
        return next();
      }

      const clientIp = req.ip || LOCALHOST_IP;
      const currentTime = Date.now();

      // Check store size and force cleanup if needed
      if (this.rateLimitStore.size >= this.MAX_STORE_SIZE * this.MAX_STORE_SIZE_PERCENTAGE) {
        this.forceCleanup(currentTime);
      }

      if (this.isRateLimited(clientIp, currentTime)) {
        this.metrics.blockedRequests++;
        res.status(HttpStatus.TOO_MANY_REQUESTS).json({
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          message:
            this.config.errorMessages?.rateLimitExceeded ||
            'Too many requests. Please try again later.',
          error: 'Too Many Requests',
        });
        return;
      }

      const token = req.header(this.config.token?.headerName || 'X-SECURITY-TOKEN');
      if (!token || !this.isValidXSecureToken(token)) {
        if (this.config.rateLimit?.enabled && this.rateLimitStore.size < this.MAX_STORE_SIZE) {
          this.incrementFailedAttempts(clientIp, currentTime);
        }
        this.metrics.blockedRequests++;
        res.status(HttpStatus.FORBIDDEN).json({
          statusCode: HttpStatus.FORBIDDEN,
          message: this.config.errorMessages?.invalidToken || 'Invalid XSECURITY token',
          error: 'Forbidden',
        });
        return;
      }

      this.rateLimitStore.delete(clientIp);
      next();
    } catch (error) {
      this.metrics.blockedRequests++;
      // Handle any unexpected errors
      res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        message: 'Internal security error',
        error: 'Internal Server Error',
      });
    }
  }

  public getCleanupInterval() {
    return this.cleanupInterval;
  }

  private normalizePath(path: string): string {
    const pathWithoutQuery = path.split('?')[0];
    return pathWithoutQuery.startsWith('/') ? pathWithoutQuery : `/${pathWithoutQuery}`;
  }

  private isExcludedPath(path: string): boolean {
    const normalizedPath = this.normalizePath(path);
    return this.excludePatterns.some((pattern) => {
      // If pattern is RegExp, use test method
      if (pattern instanceof RegExp) {
        return pattern.test(normalizedPath);
      }
      const normalizedPattern = this.normalizePath(pattern);
      const patternSegments = normalizedPattern.split('/').filter(Boolean);
      const pathSegments = normalizedPath.split('/').filter(Boolean);

      // If segments length doesn't match and there's no wildcard, return false
      if (patternSegments.length !== pathSegments.length && !pattern.includes('*')) {
        return false;
      }

      for (let i = 0; i < patternSegments.length; i++) {
        const patternSegment = patternSegments[i];
        const pathSegment = pathSegments[i];

        // Handle wildcards
        if (patternSegment === '*') {
          if (i === patternSegments.length - 1) {
            return true;
          }
          continue;
        }
        if (patternSegment.startsWith(':')) {
          if (!pathSegment) return false;
          continue;
        }
        if (patternSegment.toLowerCase() !== pathSegment.toLowerCase()) {
          return false;
        }
      }

      return true;
    });
  }

  private checkAndCleanup(): void {
    const currentTime = Date.now();
    this.cleanupRateLimits(currentTime);
    this.checkMemoryUsage();

    // Update metrics
    this.metrics.currentStoreSize = this.rateLimitStore.size;
    this.metrics.peakStoreSize = Math.max(this.metrics.peakStoreSize, this.rateLimitStore.size);
    this.metrics.lastCleanupTime = currentTime;
  }

  private forceCleanup(currentTime: number): void {
    let cleanedEntries = 0;

    // If we're at max capacity, perform aggressive cleanup
    if (this.rateLimitStore.size >= this.MAX_STORE_SIZE) {
      for (const [clientIp, rateLimit] of this.rateLimitStore.entries()) {
        // Remove entries that are over 50% of their time window
        const timeWindow = (this.config.rateLimit?.decayMinutes || 1) * 60 * 1000;
        const elapsedTime = currentTime - (rateLimit.resetTime - timeWindow);

        if (elapsedTime > timeWindow * this.TIME_WINDOW_TRIGGER_THRESHOLD) {
          this.rateLimitStore.delete(clientIp);
          cleanedEntries++;
        }

        // Break if we've cleaned enough entries
        if (
          this.rateLimitStore.size <
          this.MAX_STORE_SIZE * this.MAX_STORE_SIZE_CLEANUP_THRESHOLD
        ) {
          break;
        }
      }

      if (cleanedEntries > 0) {
        console.warn(`XSecurity: Emergency cleanup performed. Removed ${cleanedEntries} entries.`);
      }
    }
  }

  private cleanupRateLimits(currentTime: number): void {
    let cleanedEntries = 0;

    for (const [clientIp, rateLimit] of this.rateLimitStore.entries()) {
      if (currentTime > rateLimit.resetTime) {
        this.rateLimitStore.delete(clientIp);
        cleanedEntries++;
      }
    }

    // Log significant cleanups
    if (cleanedEntries > 100) {
      console.log(
        `XSecurity: Cleaned ${cleanedEntries} entries. Current store size: ${this.rateLimitStore.size}`,
      );
    }
  }

  private checkMemoryUsage(): void {
    const processMemory = process.memoryUsage().rss;
    const systemTotalMemory = os.totalmem();
    const processMemoryPercent = (processMemory / systemTotalMemory) * 100;

    if (processMemoryPercent > this.FORCE_CLEANUP_MEMORY_THRESHOLD) {
      console.warn(
        `XSecurity: High process memory usage (${processMemoryPercent.toFixed(2)}% of system memory). Forcing cleanup...`,
      );
      this.forceCleanup(Date.now());
    }
  }

  public getMetrics(): MetricsInfo {
    return {
      ...this.metrics,
      currentStoreSize: this.rateLimitStore.size,
    };
  }

  private isRateLimited(clientIp: string, currentTime: number): boolean {
    const rateLimit = this.rateLimitStore.get(clientIp);
    if (!rateLimit) return false;

    if (currentTime > rateLimit.resetTime) {
      this.rateLimitStore.delete(clientIp);
      return false;
    }

    return rateLimit.count >= (this.config.rateLimit?.maxAttempts || 5);
  }

  private incrementFailedAttempts(clientIp: string, currentTime: number): void {
    const decayMs = (this.config.rateLimit?.decayMinutes || 1) * 60 * 1000;

    const rateLimit = this.rateLimitStore.get(clientIp) || {
      count: 0,
      resetTime: currentTime + decayMs,
    };
    rateLimit.count++;
    this.rateLimitStore.set(clientIp, rateLimit);
  }

  private isValidXSecureToken(signedToken: string): boolean {
    try {
      if (!this.secret) {
        throw new Error('Security secret is not configured');
      }
      const parts = signedToken.split('.');
      if (parts.length !== 2) return false;

      const [token, signature] = parts;
      const expectedSignature = crypto
        .createHmac('sha256', this.secret)
        .update(token)
        .digest('hex');

      if (!crypto.timingSafeEqual(Buffer.from(expectedSignature), Buffer.from(signature))) {
        return false;
      }

      const payload = JSON.parse(Buffer.from(token, 'base64').toString('utf-8'));
      if (!payload || !payload.expiry) return false;

      return Date.now() / 1000 < payload.expiry;
    } catch {
      return false;
    }
  }

  onModuleDestroy() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
  }
}

import {
  HttpException,
  HttpStatus,
  Injectable,
  NestMiddleware,
  OnModuleDestroy,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import { NextFunction, Request, Response } from 'express';
import { XSecurityConfig } from '../interfaces/config.interface';
import { mergeConfig } from '../utils/config.utils';

interface TokenPayload {
  expiry: number;
  [key: string]: unknown;
}

interface RateLimitInfo {
  count: number;
  resetTime: number;
}

@Injectable()
export class XSecurityMiddleware implements NestMiddleware, OnModuleDestroy {
  private readonly config: XSecurityConfig;
  private readonly rateLimitStore = new Map<string, RateLimitInfo>();
  private readonly cleanupInterval: NodeJS.Timeout;

  constructor(
    private configService: ConfigService,
    userConfig?: XSecurityConfig,
  ) {
    this.config = mergeConfig(userConfig);

    // Setup periodic cleanup with configurable interval
    const cleanupMinutes = this.config.rateLimit?.cleanupInterval || 5;
    this.cleanupInterval = setInterval(
      () => {
        this.cleanupRateLimits();
      },
      cleanupMinutes * 60 * 1000,
    );
  }

  use(req: Request, res: Response, next: NextFunction): void {
    try {
      const envEnabled = this.configService.get<string>(
        this.config.environment?.enabled || 'XSECURITY_ENABLED',
      );

      if (this.config.enabled === false || envEnabled === 'false') {
        return next();
      }

      const clientIp = req.ip || '127.0.0.1';
      const currentTime = Date.now();

      if (this.isRateLimited(clientIp, currentTime)) {
        throw new HttpException(
          this.config.errorMessages?.rateLimitExceeded ||
            'Too many requests. Please try again later.',
          HttpStatus.TOO_MANY_REQUESTS,
        );
      }

      const token = req.header(this.config.token?.headerName || 'X-SECURITY-TOKEN');
      if (!token || !this.isValidXSecureToken(token)) {
        this.incrementFailedAttempts(clientIp, currentTime);
        throw new HttpException(
          this.config.errorMessages?.invalidToken || 'Invalid XSECURITY token',
          HttpStatus.FORBIDDEN,
        );
      }

      this.rateLimitStore.delete(clientIp);
      next();
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException('Internal security error', HttpStatus.INTERNAL_SERVER_ERROR);
    }
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
      const sharedSecretKey = this.configService.get<string>(
        this.config.environment?.secret || 'XSECURITY_SECRET',
      );

      if (!sharedSecretKey) {
        throw new Error('Security secret is not configured');
      }

      const parts = signedToken.split('.');
      if (parts.length !== 2) return false;

      const [token, signature] = parts;
      if (!token || !signature) return false;

      const expectedSignature = crypto
        .createHmac('sha256', sharedSecretKey)
        .update(token)
        .digest('hex');

      if (!crypto.timingSafeEqual(Buffer.from(expectedSignature), Buffer.from(signature))) {
        return false;
      }

      const payload = JSON.parse(Buffer.from(token, 'base64').toString('utf-8')) as TokenPayload;

      if (!payload || !payload.expiry) return false;

      const expirySeconds = this.config.token?.expirySeconds || 10;
      return (
        Date.now() / 1000 < payload.expiry && payload.expiry <= Date.now() / 1000 + expirySeconds
      );
    } catch {
      return false;
    }
  }

  private cleanupRateLimits(): void {
    const currentTime = Date.now();
    for (const [clientIp, rateLimit] of this.rateLimitStore.entries()) {
      if (currentTime > rateLimit.resetTime) {
        this.rateLimitStore.delete(clientIp);
      }
    }
  }

  onModuleDestroy() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
  }
}

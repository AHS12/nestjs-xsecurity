import { HttpException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import * as crypto from 'crypto';
import { Request, Response } from 'express';
import { XSecurityMiddleware } from '../middleware/x-security.middleware';

describe('XSecurityMiddleware', () => {
  let middleware: XSecurityMiddleware;
  let configService: ConfigService;
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: jest.Mock;

  const generateXsecurityToken = (secretKey: string, expiryOffset: number = 10): string => {
    // Calculate expiry timestamp (default 10 seconds from current time)
    const expiryTimestamp = Math.floor(Date.now() / 1000) + expiryOffset;

    // Create payload object with expiry timestamp
    const payload = { expiry: expiryTimestamp };

    // Encode payload to Base64
    const token = Buffer.from(JSON.stringify(payload)).toString('base64');

    // Create HMAC signature using SHA-256 hash function
    const hmac = crypto.createHmac('sha256', secretKey);
    hmac.update(token);
    const signature = hmac.digest('hex');

    // Combine token and signature separated by a period
    return `${token}.${signature}`;
  };

  beforeEach(async () => {
    const testSecretKey = 'test-secret-key-12345';

    const mockConfigService = {
      get: jest.fn((key: string): string => {
        const values: { [key: string]: string } = {
          XSECURITY_ENABLED: 'true',
          XSECURITY_SECRET: testSecretKey,
        };
        return values[key] || '';
      }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
      ],
    }).compile();

    configService = module.get<ConfigService>(ConfigService);

    // Create middleware with custom config to match actual implementation
    const customConfig = {
      token: {
        expirySeconds: 10, // Match the default in the middleware
        headerName: 'X-SECURITY-TOKEN',
      },
    };

    middleware = new XSecurityMiddleware(configService, customConfig);

    mockReq = {
      ip: '127.0.0.1',
      header: jest.fn(),
    };
    mockRes = {};
    mockNext = jest.fn();
  });

  afterEach(() => {
    if (middleware['cleanupInterval']) {
      clearInterval(middleware['cleanupInterval']);
    }
    jest.clearAllMocks();
  });

  describe('Token Validation', () => {
    it('should pass with valid token', () => {
      const secretKey = configService.get('XSECURITY_SECRET');
      const validToken = generateXsecurityToken(secretKey, 5);
      // Set up request mock
      mockReq.header = jest.fn().mockImplementation((name: string): string | undefined => {
        return name === 'X-SECURITY-TOKEN' ? validToken : undefined;
      });

      middleware.use(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it('should reject token with expiry too far in future', () => {
      const secretKey = configService.get('XSECURITY_SECRET');
      // Generate token with 15 seconds expiry (beyond the 10 second window)
      const invalidToken = generateXsecurityToken(secretKey, 15);

      mockReq.header = jest.fn().mockReturnValue(invalidToken);

      expect(() => middleware.use(mockReq as Request, mockRes as Response, mockNext)).toThrow(
        HttpException,
      );
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject expired token', () => {
      const secretKey = configService.get('XSECURITY_SECRET');
      const expiredToken = generateXsecurityToken(secretKey, -1); // expired 1 second ago
      mockReq.header = jest.fn().mockReturnValue(expiredToken);

      expect(() => middleware.use(mockReq as Request, mockRes as Response, mockNext)).toThrow(
        HttpException,
      );
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject token with invalid signature', () => {
      const secretKey = configService.get('XSECURITY_SECRET');
      const [tokenPart] = generateXsecurityToken(secretKey, 5).split('.');
      const invalidToken = `${tokenPart}.invalid-signature`;

      mockReq.header = jest.fn().mockReturnValue(invalidToken);

      expect(() => middleware.use(mockReq as Request, mockRes as Response, mockNext)).toThrow(
        HttpException,
      );
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject missing token', () => {
      mockReq.header = jest.fn().mockReturnValue(undefined);

      expect(() => middleware.use(mockReq as Request, mockRes as Response, mockNext)).toThrow(
        HttpException,
      );
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('Rate Limiting', () => {
    it('should allow requests within rate limit', () => {
      const secretKey = configService.get('XSECURITY_SECRET');
      const validToken = generateXsecurityToken(secretKey, 5);
      mockReq.header = jest.fn().mockReturnValue(validToken);

      for (let i = 0; i < 5; i++) {
        middleware.use(mockReq as Request, mockRes as Response, mockNext);
      }
      expect(mockNext).toHaveBeenCalledTimes(5);
    });

    it('should block requests exceeding rate limit', () => {
      mockReq.header = jest.fn().mockReturnValue('invalid-token');
      // Simulate max attempts (default is 5)
      for (let i = 0; i < 5; i++) {
        expect(() => middleware.use(mockReq as Request, mockRes as Response, mockNext)).toThrow(
          HttpException,
        );
      }
      // The 6th attempt should be rate limited
      expect(() => middleware.use(mockReq as Request, mockRes as Response, mockNext)).toThrow(
        /Too many requests/,
      );
    });
  });
});

import * as crypto from 'crypto';
import { Request, Response } from 'express';
import { XSecurityConfig } from '../interfaces/config.interface';
import { XSecurityMiddleware } from '../middleware/x-security.middleware';

describe('XSecurityMiddleware', () => {
  let middleware: XSecurityMiddleware;
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: jest.Mock;
  let testSecretKey: string;

  const generateXsecurityToken = (secretKey: string, expiryOffset: number = 10): string => {
    const expiryTimestamp = Math.floor(Date.now() / 1000) + expiryOffset;
    const payload = { expiry: expiryTimestamp };
    const token = Buffer.from(JSON.stringify(payload)).toString('base64');
    const hmac = crypto.createHmac('sha256', secretKey);
    hmac.update(token);
    const signature = hmac.digest('hex');
    return `${token}.${signature}`;
  };

  beforeEach(async () => {
    testSecretKey = 'test-secret-key-12345';

    const customConfig: XSecurityConfig = {
      token: {
        expirySeconds: 10,
        headerName: 'X-SECURITY-TOKEN',
      },
      secret: testSecretKey,
    };

    middleware = new XSecurityMiddleware(customConfig);

    // Mock request object
    mockReq = {
      ip: '127.0.0.1',
      header: jest.fn(),
      originalUrl: '/test',
      url: '/test',
    };

    // Mock response object with chaining methods
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };

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
      const validToken = generateXsecurityToken(testSecretKey, 5);
      mockReq.header = jest.fn().mockImplementation((name: string): string | undefined => {
        return name === 'X-SECURITY-TOKEN' ? validToken : undefined;
      });

      middleware.use(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(mockRes.status).not.toHaveBeenCalled();
    });

    it('should reject token with invalid signature', () => {
      const [tokenPart] = generateXsecurityToken(testSecretKey, 5).split('.');
      const invalidToken = `${tokenPart}.invalid-signature`;

      mockReq.header = jest.fn().mockReturnValue(invalidToken);

      middleware.use(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 403,
          message: 'Invalid XSECURITY token',
        }),
      );
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject missing token', () => {
      mockReq.header = jest.fn().mockReturnValue(undefined);

      middleware.use(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 403,
          message: 'Invalid XSECURITY token',
        }),
      );
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('Rate Limiting', () => {
    it('should allow requests within rate limit', () => {
      const validToken = generateXsecurityToken(testSecretKey, 5);
      mockReq.header = jest.fn().mockReturnValue(validToken);

      for (let i = 0; i < 5; i++) {
        middleware.use(mockReq as Request, mockRes as Response, mockNext);
      }

      expect(mockNext).toHaveBeenCalledTimes(5);
      expect(mockRes.status).not.toHaveBeenCalled();
    });

    it('should block requests exceeding rate limit', () => {
      mockReq.header = jest.fn().mockReturnValue('invalid-token');

      // Simulate max attempts (default is 5)
      for (let i = 0; i < 5; i++) {
        middleware.use(mockReq as Request, mockRes as Response, mockNext);
        expect(mockRes.status).toHaveBeenCalledWith(403);
      }

      // Reset mock counts
      jest.clearAllMocks();

      // The 6th attempt should be rate limited
      middleware.use(mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(429);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 429,
          message: 'Too many requests. Please try again later.',
        }),
      );
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('Path Exclusion', () => {
    it('should skip middleware for excluded paths', () => {
      const configWithExcludes: XSecurityConfig = {
        secret: testSecretKey,
        exclude: ['/health', '/metrics', '/api/*'],
      };

      const middlewareWithExcludes = new XSecurityMiddleware(configWithExcludes);

      // Test exact match
      mockReq.originalUrl = '/health';
      middlewareWithExcludes.use(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
      expect(mockRes.status).not.toHaveBeenCalled();

      // Test wildcard match
      mockReq.originalUrl = '/api/users';
      middlewareWithExcludes.use(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
      expect(mockRes.status).not.toHaveBeenCalled();
    });
  });
});

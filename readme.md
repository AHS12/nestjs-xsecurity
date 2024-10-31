# nestjs-xsecurity

<div align="center">

🔐 Enterprise-grade security middleware for NestJS applications with token validation, rate limiting, and path exclusion.

[![npm version](https://badge.fury.io/js/nestjs-xsecurity.svg)](https://badge.fury.io/js/nestjs-xsecurity)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![NestJS](https://img.shields.io/badge/NestJS-Compatible-red.svg)](https://nestjs.com/)

</div>

## 🌟 Features

- **Token-based Security**
  - HMAC-SHA256 signature validation
  - Configurable token expiration
  - Custom header support

- **Rate Limiting**
  - IP-based request throttling
  - Configurable attempt limits
  - Automatic cleanup of expired records

- **Path Control**
  - Exclude specific routes
  - Support for wildcards and patterns
  - RegExp compatibility

- **Developer Experience**
  - Full TypeScript support
  - Comprehensive configuration options
  - CLI setup tool
  - Cross-platform token generators

## 📦 Installation

```bash
# Using npm
npm install nestjs-xsecurity

# Using yarn
yarn add nestjs-xsecurity

# Using pnpm
pnpm add nestjs-xsecurity
```

## 🚀 Quick Start

### 1. Initialize with CLI

```bash
npx nestjs-xsecurity install
```

This command will:
- Generate a secure random secret
- Set up environment variables
- Create initial configuration

### 2. Module Registration

Choose one of these approaches:

#### ⭐ Recommended: Async Configuration

```typescript
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { XSecurityModule } from 'nestjs-xsecurity';

@Module({
  imports: [
    ConfigModule.forRoot(),
    XSecurityModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        enabled: config.get('XSECURITY_ENABLED', true),
        secret: config.get('XSECURITY_SECRET'),
        rateLimit: {
          maxAttempts: config.get('XSECURITY_MAX_ATTEMPTS', 5),
          decayMinutes: config.get('XSECURITY_DECAY_MINUTES', 1),
        },
        exclude: ['/health', '/metrics', '/api/docs/*'],
      }),
    }),
  ],
})
export class AppModule {}
```

#### Alternative: Static Configuration

```typescript
import { Module } from '@nestjs/common';
import { XSecurityModule } from 'nestjs-xsecurity';

@Module({
  imports: [
    XSecurityModule.register({
      enabled: true,
      secret: process.env.XSECURITY_SECRET,
      rateLimit: {
        maxAttempts: 5,
        decayMinutes: 1,
      },
      exclude: ['/health'],
    }),
  ],
})
export class AppModule {}
```

## 🔧 Configuration

### Environment Variables

```env
# Required
XSECURITY_SECRET=your-secure-secret-key

# Optional
XSECURITY_ENABLED=true
XSECURITY_MAX_ATTEMPTS=5
XSECURITY_DECAY_MINUTES=1
```

### Configuration Options

```typescript
interface XSecurityConfig {
  // Enable/disable middleware
  enabled?: boolean;

  // Your secret key for token validation
  secret?: string;

  // Rate limiting settings
  rateLimit?: {
    maxAttempts?: number;    // Default: 5
    decayMinutes?: number;   // Default: 1
    cleanupInterval?: number; // Default: 5
  };

  // Token configuration
  token?: {
    headerName?: string;     // Default: 'X-SECURITY-TOKEN'
    expirySeconds?: number;  // Default: 10 (10 seconds)
  };

  // Paths to exclude from security checks
  exclude?: Array<string | RegExp>;

  // Custom error messages
  errorMessages?: {
    rateLimitExceeded?: string;
    invalidToken?: string;
  };
}
```

## 🔑 Token Implementation

### Node.js / TypeScript

```typescript
import crypto from 'crypto';

function generateXsecurityToken(secretKey: string, expirySeconds = 300): string {
  const expiryTimestamp = Math.floor(Date.now() / 1000) + expirySeconds;
  const payload = { expiry: expiryTimestamp };
  const token = Buffer.from(JSON.stringify(payload)).toString('base64');
  const signature = crypto
    .createHmac('sha256', secretKey)
    .update(token)
    .digest('hex');

  return `${token}.${signature}`;
}

// Usage
const token = generateXsecurityToken('your-secret-key');
```

### Python

```python
import hmac
import json
import base64
import hashlib
import time

def generate_xsecurity_token(secret_key: str, expiry_seconds: int = 300) -> str:
    expiry = int(time.time()) + expiry_seconds
    payload = {'expiry': expiry}

    # Create token
    token = base64.b64encode(
        json.dumps(payload).encode()
    ).decode()

    # Generate signature
    signature = hmac.new(
        secret_key.encode(),
        token.encode(),
        hashlib.sha256
    ).hexdigest()

    return f"{token}.{signature}"
```

### Flutter / Dart

```dart
import 'dart:convert';
import 'package:crypto/crypto.dart';

String generateXsecurityToken(String secretKey, {int expirySeconds = 300}) {
  final expiry = DateTime.now().millisecondsSinceEpoch ~/ 1000 + expirySeconds;
  final payload = {'expiry': expiry};

  final token = base64Url.encode(utf8.encode(jsonEncode(payload)));
  final signature = Hmac(sha256, utf8.encode(secretKey))
      .convert(utf8.encode(token))
      .toString();

  return '$token.$signature';
}
```

## 📝 Examples

### Making a Secured Request

```typescript
// Client-side
const token = generateXsecurityToken(secretKey);

await fetch('https://api.example.com/data', {
  headers: {
    'X-SECURITY-TOKEN': token
  }
});
```

### Path Exclusion Patterns

```typescript
XSecurityModule.register({
  exclude: [
    '/health',           // Exact match
    '/api/*',           // Wildcard match
    '/v1/:param/data',  // Parameter match
    /^\/public\/.*/     // RegExp match
  ]
});
```

### Error Responses

```typescript
// Rate limit exceeded
{
  "statusCode": 429,
  "message": "Too many requests. Please try again later.",
  "error": "Too Many Requests"
}

// Invalid token
{
  "statusCode": 403,
  "message": "Invalid XSECURITY token",
  "error": "Forbidden"
}
```

## 🛠️ CLI Reference

```bash
npx nestjs-xsecurity <command>

Commands:
  install     Initialize security configuration
  init        Alias for install
  help        Show help information
```

## 🔒 Security Best Practices

1. **Secret Management**
   - Use environment variables for secrets
   - Implement secret rotation
   - Never expose secrets in client code

2. **Token Handling**
   - Use HTTPS for all requests
   - Implement token refresh mechanism
   - Monitor token usage patterns

3. **Rate Limiting**
   - Adjust limits based on your API's capacity
   - Monitor rate limit hits
   - Implement progressive delays

## 🤝 Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) before submitting changes.

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ✨ Creator

[Azizul Hakim](https://github.com/ahs12)

---

<div align="center">

Made with ❤️ for the NestJS community

</div>

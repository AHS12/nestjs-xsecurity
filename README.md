# nestjs-xsecurity

<div align="center">

🔐 Robust security middleware for NestJS applications with token validation, rate limiting, and path exclusion.

[![npm version](https://badge.fury.io/js/nestjs-xsecurity.svg)](https://badge.fury.io/js/nestjs-xsecurity)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![NestJS](https://img.shields.io/badge/NestJS-Compatible-green.svg)](https://nestjs.com/)

</div>

## 📦 Installation

```bash
# Using npm
npm install nestjs-xsecurity

# Using yarn
yarn add nestjs-xsecurity

# Using pnpm
pnpm add nestjs-xsecurity
```

## 📖 Documentation

- [Quick Start Guide](https://github.com/ahs12/nestjs-xsecurity?tab=readme-ov-file#-quick-start) (below)
- [Complete Documentation](https://github.com/ahs12/nestjs-xsecurity/wiki) - Visit the [Wiki](https://github.com/ahs12/nestjs-xsecurity/wiki) for:
  - Advanced Configuration Examples
  - Security Best Practices
  - Troubleshooting
  - And More!

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
  - Wiki documentation. [Wiki](https://github.com/ahs12/nestjs-xsecurity/wiki)


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
          enabled: config.get('XSECURITY_RATE_LIMIT_ENABLED', true),
          maxAttempts: config.get('XSECURITY_MAX_ATTEMPTS', 5),
          decayMinutes: config.get('XSECURITY_DECAY_MINUTES', 1),
          storeLimit: config.get('XSECURITY_RATE_LIMIT_STORE_LIMIT', 10000),
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
        enabled: true,
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

Details configuration options can be found in this [Wiki Page](https://github.com/AHS12/nestjs-xsecurity/wiki/Configuration-Options#configuration-sections).

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
    enabled?: boolean;      // Default: true
    maxAttempts?: number;    // Default: 5
    decayMinutes?: number;   // Default: 1
    cleanupInterval?: number; // Default: 5
    storeLimit?: number;      // Default: 10000
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
  const randomBytes = crypto.randomBytes(16).toString('hex'); // Add randomness
  const payload = {
    expiry: expiryTimestamp,
    nonce: randomBytes,
    iat: Date.now()
  };

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
import time
import json
import hmac
import base64
import secrets
import hashlib
from typing import Optional

def generate_xsecurity_token(secret_key: str, expiry_seconds: int = 300) -> str:
    """
    Generate a secure token with expiry and nonce.

    Args:
        secret_key (str): Secret key for signing
        expiry_seconds (int): Token validity duration in seconds

    Returns:
        str: Generated security token
    """
    expiry_timestamp = int(time.time()) + expiry_seconds
    random_bytes = secrets.token_hex(16)  # 16 bytes = 32 hex chars

    payload = {
        "expiry": expiry_timestamp,
        "nonce": random_bytes,
        "iat": int(time.time() * 1000)  # milliseconds
    }

    # Convert payload to base64
    token = base64.b64encode(
        json.dumps(payload).encode('utf-8')
    ).decode('utf-8')

    # Generate signature
    signature = hmac.new(
        secret_key.encode('utf-8'),
        token.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    return f"{token}.{signature}"
```

### Flutter / Dart

```dart
import 'dart:convert';
import 'dart:math';
import 'package:crypto/crypto.dart';

class XSecurityToken {
  static String generate(String secretKey, {int expirySeconds = 300}) {
    final expiryTimestamp = (DateTime.now().millisecondsSinceEpoch ~/ 1000) + expirySeconds;

    // Generate random bytes for nonce
    final random = Random.secure();
    final randomBytes = List<int>.generate(16, (i) => random.nextInt(256));
    final nonce = randomBytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

    final payload = {
      'expiry': expiryTimestamp,
      'nonce': nonce,
      'iat': DateTime.now().millisecondsSinceEpoch
    };

    // Convert payload to base64
    final token = base64Encode(utf8.encode(jsonEncode(payload)));

    // Generate signature
    final hmacSha256 = Hmac(sha256, utf8.encode(secretKey));
    final signature = hmacSha256.convert(utf8.encode(token)).toString();

    return '$token.$signature';
  }
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
   - Never expose secrets in client code


2. **Rate Limiting**
   - Adjust limits based on your API's capacity
   - Monitor rate limit hits
   - Implement progressive delays

## 🤝 Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) before submitting changes.


## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ✨ Creator

[Azizul Hakim](https://github.com/ahs12)

---

<div align="center">

Made with ❤️ for the NestJS community

</div>

# nestjs-xsecurity

🔐 A robust security middleware for NestJS applications with token validation and rate limiting capabilities.

[![npm version](https://badge.fury.io/js/nestjs-xsecurity.svg)](https://badge.fury.io/js/nestjs-xsecurity)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔑 Token-based security validation
- 🚦 IP-based rate limiting
- ⚙️ Highly configurable settings
- 📘 Full TypeScript support
- 🛠️ CLI setup tool
- 🔄 Token generation utilities for multiple platforms

## Installation

```bash
npm install nestjs-xsecurity
```

## Setup

Initialize the security configuration using our CLI tool:

```bash
npx nestjs-xsecurity install
```

This command will:
- Generate a cryptographically secure random secret
- Create/update `.env` file with required variables
- Enable the security middleware

## Implementation

### 1. Register the Module

```typescript
// app.module.ts
import { XSecurityModule } from 'nestjs-xsecurity';

@Module({
  imports: [
    XSecurityModule.register({
      enabled: true,
      token: {
        headerName: 'X-SECURITY-TOKEN'
      }
    })
  ]
})
export class AppModule {}
```

### 2. Apply Middleware

Choose one of these methods:

**Option A: NestJS Module Approach (Recommended)**
```typescript
// app.module.ts
import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { XSecurityMiddleware } from 'nestjs-xsecurity';

@Module({
  imports: [XSecurityModule.register()]
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(XSecurityMiddleware).forRoutes('*');
  }
}
```

**Option B: Express-style Approach**
```typescript
// main.ts
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(app.get(XSecurityMiddleware));
  await app.listen(3000);
}
```

### 3. Environment Configuration

```bash
XSECURITY_ENABLED=true
XSECURITY_SECRET=your-secret-key
```

## Token Implementation

### TypeScript/JavaScript
```typescript
import crypto from 'crypto';

export function generateXsecurityToken(secretKey: string): string {
  const expiryTimestamp = Math.floor(Date.now() / 1000) + 60; // 1 minute expiry
  const payload = { expiry: expiryTimestamp };
  const token = Buffer.from(JSON.stringify(payload)).toString('base64');
  const signature = crypto
    .createHmac('sha256', secretKey)
    .update(token)
    .digest('hex');

  return `${token}.${signature}`;
}
```

### Flutter/Dart
```dart
import 'dart:convert';
import 'package:crypto/crypto.dart';

String generateXsecurityToken(String secretKey) {
  final expiryTimestamp = DateTime.now().millisecondsSinceEpoch ~/ 1000 + 60;
  final payload = {'expiry': expiryTimestamp};
  final token = base64Url.encode(utf8.encode(jsonEncode(payload)));
  final signature = Hmac(sha256, utf8.encode(secretKey))
    .convert(utf8.encode(token))
    .toString();

  return '$token.$signature';
}
```

## Usage Examples

### Token Format
```
eyJleHBpcnkiOjE3MTE5MDE2NjJ9.89b9c45cffee0072ea160441e2462a7ae2de8b484f5d1f5bf4e57f90b1340e0c
```

### HTTP Request Header
```http
X-SECURITY-TOKEN: eyJleHBicnkiOjE3MTE5MDE2NjJ9.89b9c45cffee0072ea160441e2462a7ae2de8b484f5d1f5bf4e57f90b1340e0c
```

### Error Response
```json
{
  "statusCode": 403,
  "message": "Invalid XSECURITY token"
}
```

## CLI Commands

```bash
npx nestjs-xsecurity <command>

Commands:
  install     Generate secret and configure environment
  init        Alias for install
  help        Show help information
```

## Security Considerations

- Store the secret key securely and never expose it in client-side code
- Use environment variables for configuration in production
- Implement proper secret key rotation procedures
- Monitor rate limiting logs for potential attacks

<!-- ## Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) for details. -->

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

[Azizul Hakim](https://github.com/ahs12)

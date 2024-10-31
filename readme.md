# nestjs-xsecurity

Secure your NestJS applications with token validation and rate limiting middleware.

## Installation

```bash
npm install nestjs-xsecurity
```

## Quick Start

1. Register the module:
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

2. Apply middleware (choose one method):

**Method A: Using NestModule**
```typescript
// app.module.ts
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(XSecurityMiddleware).forRoutes('*');
  }
}
```

**Method B: Using app.use()**
```typescript
// main.ts
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(app.get(XSecurityMiddleware));
  await app.listen(3000);
}
```

3. Set environment variables:
```bash
XSECURITY_ENABLED=true
XSECURITY_SECRET=your-secret-key
```

## Features

- Token-based security validation
- Rate limiting with IP tracking
- Configurable settings
- TypeScript support


## License

[MIT LICENSE](LICENSE)

## Author

[Azizul hakim](https://github.com/ahs12)

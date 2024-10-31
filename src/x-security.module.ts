import {
  DynamicModule,
  Global,
  InjectionToken,
  MiddlewareConsumer,
  Module,
  NestModule,
  OptionalFactoryDependency,
  Provider,
  Type,
} from '@nestjs/common';
import { XSecurityConfig } from './interfaces/config.interface';
import { XSecurityMiddleware } from './middleware/x-security.middleware';

export const XSECURITY_CONFIG = 'XSECURITY_CONFIG';

export interface XSecurityOptionsFactory {
  createXSecurityOptions(): Promise<XSecurityConfig> | XSecurityConfig;
}

// Split into two separate interfaces for better type safety
export interface XSecurityAsyncOptionsFactory {
  imports?: any[];
  useFactory: (...args: any[]) => Promise<XSecurityConfig> | XSecurityConfig;
  inject?: Array<InjectionToken | OptionalFactoryDependency>;
}

export interface XSecurityAsyncOptionsClass {
  imports?: any[];
  useClass: Type<XSecurityOptionsFactory>;
  inject?: Array<InjectionToken | OptionalFactoryDependency>;
}

export interface XSecurityAsyncOptionsExisting {
  imports?: any[];
  useExisting: Type<XSecurityOptionsFactory>;
  inject?: Array<InjectionToken | OptionalFactoryDependency>;
}

export type XSecurityAsyncOptions =
  | XSecurityAsyncOptionsFactory
  | XSecurityAsyncOptionsClass
  | XSecurityAsyncOptionsExisting;

// Type guard functions
function isFactoryAsync(options: XSecurityAsyncOptions): options is XSecurityAsyncOptionsFactory {
  return 'useFactory' in options;
}

function isClassAsync(options: XSecurityAsyncOptions): options is XSecurityAsyncOptionsClass {
  return 'useClass' in options;
}

function isExistingAsync(options: XSecurityAsyncOptions): options is XSecurityAsyncOptionsExisting {
  return 'useExisting' in options;
}

@Global()
@Module({})
export class XSecurityModule implements NestModule {
  static register(config: XSecurityConfig = {}): DynamicModule {
    return {
      module: XSecurityModule,
      providers: [
        {
          provide: XSECURITY_CONFIG,
          useValue: config,
        },
        XSecurityMiddleware,
      ],
      exports: [XSecurityMiddleware],
    };
  }

  static registerAsync(options: XSecurityAsyncOptions): DynamicModule {
    return {
      module: XSecurityModule,
      imports: options.imports || [],
      providers: [...this.createAsyncProviders(options), XSecurityMiddleware],
      exports: [XSecurityMiddleware],
    };
  }

  private static createAsyncProviders(options: XSecurityAsyncOptions): Provider[] {
    if (isFactoryAsync(options)) {
      return [
        {
          provide: XSECURITY_CONFIG,
          useFactory: options.useFactory,
          inject: options.inject || [],
        },
      ];
    }

    if (isClassAsync(options)) {
      return [
        {
          provide: XSECURITY_CONFIG,
          useFactory: async (optionsFactory: XSecurityOptionsFactory) =>
            await optionsFactory.createXSecurityOptions(),
          inject: [options.useClass],
        },
        {
          provide: options.useClass,
          useClass: options.useClass,
        },
      ];
    }

    if (isExistingAsync(options)) {
      return [
        {
          provide: XSECURITY_CONFIG,
          useFactory: async (optionsFactory: XSecurityOptionsFactory) =>
            await optionsFactory.createXSecurityOptions(),
          inject: [options.useExisting],
        },
      ];
    }

    throw new Error(
      'Invalid XSecurityModule configuration. Please provide either useFactory, useClass, or useExisting',
    );
  }

  configure(consumer: MiddlewareConsumer) {
    consumer.apply(XSecurityMiddleware).forRoutes('*');
  }
}

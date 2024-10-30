import { DynamicModule, Module } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { XSecurityConfig } from "./interfaces/config.interface";
import { XSecurityMiddleware } from "./middleware/x-security.middleware";

@Module({})
export class XSecurityModule {
  static register(config?: XSecurityConfig): DynamicModule {
    return {
      module: XSecurityModule,
      providers: [
        {
          provide: XSecurityMiddleware,
          useFactory: (configService: ConfigService) =>
            new XSecurityMiddleware(configService, config),
          inject: [ConfigService],
        },
      ],
      exports: [XSecurityMiddleware],
    };
  }
}

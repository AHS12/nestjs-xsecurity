import { DEFAULT_CONFIG } from '../config/default.config';
import { XSecurityConfig } from '../interfaces/config.interface';
import { validateConfig } from './validation.config';

export function mergeConfig(userConfig?: XSecurityConfig): XSecurityConfig {
  const mergedConfig = {
    enabled: userConfig?.enabled ?? DEFAULT_CONFIG.enabled,
    rateLimit: {
      ...DEFAULT_CONFIG.rateLimit,
      ...userConfig?.rateLimit,
    },
    token: {
      ...DEFAULT_CONFIG.token,
      ...userConfig?.token,
    },
    environment: {
      ...DEFAULT_CONFIG.environment,
      ...userConfig?.environment,
    },
    secret: userConfig?.secret,
    exclude: userConfig?.exclude ?? DEFAULT_CONFIG.exclude,
    errorMessages: {
      ...DEFAULT_CONFIG.errorMessages,
      ...userConfig?.errorMessages,
    },
  };

  // Validate the merged configuration
  validateConfig(mergedConfig);

  return mergedConfig;
}

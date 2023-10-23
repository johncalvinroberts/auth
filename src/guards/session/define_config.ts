/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { configProvider } from '@adonisjs/core'
import { RuntimeException } from '@poppinss/utils'
import type { HttpContext } from '@adonisjs/core/http'
import type { ConfigProvider } from '@adonisjs/core/types'

import { SessionGuard } from './guard.js'
import type { GuardConfigProvider } from '../../auth/types.js'
import type {
  SessionGuardConfig,
  RememberMeProviderContract,
  SessionUserProviderContract,
  DatabaseRememberMeProviderOptions,
} from './types.js'

/**
 * Helper function to configure the session guard for
 * authentication.
 *
 * This method returns a config builder, which internally
 * returns a factory function to construct a guard
 * during HTTP requests.
 */
export function sessionGuard<UserProvider extends SessionUserProviderContract<unknown>>(
  config: SessionGuardConfig & {
    provider: ConfigProvider<UserProvider>
    tokens?: ConfigProvider<RememberMeProviderContract>
  }
): GuardConfigProvider<(ctx: HttpContext) => SessionGuard<UserProvider>> {
  return {
    async resolver(guardName, app) {
      const provider = await configProvider.resolve<UserProvider>(app, config.provider)
      if (!provider) {
        throw new RuntimeException(`Invalid user provider defined on "${guardName}" guard`)
      }

      const emitter = await app.container.make('emitter')
      const tokensProvider = config.tokens
        ? await configProvider.resolve<RememberMeProviderContract>(app, config.tokens)
        : undefined

      /**
       * Factory function needed by Authenticator to switch
       * between guards and perform authentication
       */
      return (ctx) => {
        const guard = new SessionGuard<UserProvider>(guardName, config, ctx, provider)
        if (tokensProvider) {
          guard.withRememberMeTokens(tokensProvider)
        }

        return guard.withEmitter(emitter)
      }
    },
  }
}

/**
 * Tokens provider helper to store remember me tokens
 */
export const tokensProvider: {
  db: (config: DatabaseRememberMeProviderOptions) => ConfigProvider<RememberMeProviderContract>
} = {
  db(config) {
    return configProvider.create(async (app) => {
      const db = await app.container.make('lucid.db')
      const { DatabaseRememberTokenProvider } = await import('./token_providers/main.js')
      return new DatabaseRememberTokenProvider(db, config)
    })
  },
}

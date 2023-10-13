/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { HttpContext } from '@adonisjs/core/http'

import type {
  LucidAuthenticatable,
  LucidUserProviderOptions,
  DatabaseUserProviderOptions,
} from '../core/types.js'

import type {
  SessionGuardConfig,
  RememberMeProviderContract,
  SessionUserProviderContract,
  DatabaseRememberMeProviderOptions,
} from './types.js'

import { SessionGuard } from './guard.js'
import { ConfigProvider } from '../types/main.js'
import type { DatabaseRememberTokenProvider } from './token_providers/main.js'

export { RememberMeToken } from './token.js'
export { SessionGuard }

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
): ConfigProvider<(ctx: HttpContext) => SessionGuard<UserProvider>> {
  return async (key, app) => {
    const emitter = await app.container.make('emitter')
    const provider = await config.provider('provider', app)
    const tokensProvider = config.tokens ? await config.tokens('tokens', app) : undefined

    /**
     * Factory function needed by Authenticator to switch
     * between guards and perform authentication
     */
    return (ctx) => {
      const guard = new SessionGuard<UserProvider>(key, config, ctx, provider)
      if (tokensProvider) {
        guard.withRememberMeTokens(tokensProvider)
      }

      return guard.withEmitter(emitter)
    }
  }
}

/**
 * Helpers to configure user and tokens provider
 * for the session guard
 */
export const sessionProviders: {
  users: {
    lucid: <UserModel extends LucidAuthenticatable>(
      config: LucidUserProviderOptions<UserModel> & {
        model: () => Promise<{ default: UserModel }>
      }
    ) => ConfigProvider<SessionUserProviderContract<InstanceType<UserModel>>>
    db: <User extends Record<string, any>>(
      config: DatabaseUserProviderOptions<User>
    ) => ConfigProvider<SessionUserProviderContract<User>>
  }
  tokens: {
    db: (config: DatabaseRememberMeProviderOptions) => ConfigProvider<DatabaseRememberTokenProvider>
  }
} = {
  users: {
    lucid: (config) => {
      return async () => {
        const { LucidSessionUserProvider } = await import('./user_providers/main.js')
        return new LucidSessionUserProvider(config.model, config)
      }
    },
    db: (config) => {
      return async (_, app) => {
        const db = await app.container.make('lucid.db')
        const hash = await app.container.make('hash')
        const { DatabaseSessionUserProvider } = await import('./user_providers/main.js')
        return new DatabaseSessionUserProvider(db, hash.use(), config)
      }
    },
  },
  tokens: {
    db: (config) => {
      return async (_, app) => {
        const db = await app.container.make('lucid.db')
        const { DatabaseRememberTokenProvider } = await import('./token_providers/main.js')
        return new DatabaseRememberTokenProvider(db, config)
      }
    },
  },
}

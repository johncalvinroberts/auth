/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { HttpContext } from '@adonisjs/core/http'
import type { ConfigProvider } from '@adonisjs/core/types'

import { AccessTokensGuard } from './guard.js'
import type { GuardConfigProvider } from '../../src/types.js'
import { AccessTokensLucidUserProvider } from './user_providers/lucid.js'
import type {
  LucidTokenable,
  AccessTokensUserProviderContract,
  AccessTokensLucidUserProviderOptions,
} from './types.js'

/**
 * Configures access tokens guard for authentication
 */
export function accessTokensGuard<UserProvider extends AccessTokensUserProviderContract<unknown>>(
  userProvider: UserProvider | ConfigProvider<UserProvider>
): GuardConfigProvider<(ctx: HttpContext) => AccessTokensGuard<UserProvider>> {
  return {
    async resolver(name, app) {
      const emitter = await app.container.make('emitter')
      const provider = 'resolver' in userProvider ? await userProvider.resolver(app) : userProvider
      return (ctx) => new AccessTokensGuard(name, ctx, emitter as any, provider)
    },
  }
}

/**
 * Configures user provider that uses Lucid models to verify
 * access tokens and find users during authentication.
 */
export function accessTokensLucidProvider<
  TokenableProperty extends string,
  Model extends LucidTokenable<TokenableProperty>,
>(
  config: AccessTokensLucidUserProviderOptions<TokenableProperty, Model>
): AccessTokensLucidUserProvider<TokenableProperty, Model> {
  return new AccessTokensLucidUserProvider(config)
}

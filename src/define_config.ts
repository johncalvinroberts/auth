/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { AuthenticatorGuardFactory, ConfigProvider } from './types/main.js'

/**
 * Define configuration for the auth package. The function returns
 * a config provider that is invoked inside the auth service
 * provider
 */
export function defineConfig<
  KnownGuards extends Record<string, AuthenticatorGuardFactory>,
>(config: {
  default: keyof KnownGuards
  guards: { [K in keyof KnownGuards]: ConfigProvider<KnownGuards[K]> }
}): ConfigProvider<{
  default: keyof KnownGuards
  guards: { [K in keyof KnownGuards]: KnownGuards[K] }
}> {
  return async function (_, app) {
    const guardsList = Object.keys(config.guards) as (keyof KnownGuards)[]
    const guards = {} as { [K in keyof KnownGuards]: KnownGuards[K] }

    for (let guard of guardsList) {
      guards[guard] = await config.guards[guard](guard as string, app)
    }

    return {
      default: config.default,
      guards,
    }
  }
}

/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/// <reference types="@adonisjs/lucid/database_provider" />

import { configProvider } from '@adonisjs/core'
import type { ConfigProvider } from '@adonisjs/core/types'

import type { GuardConfigProvider, GuardFactory } from './types.js'
import type { LucidUserProvider, DatabaseUserProvider } from './user_providers/main.js'
import type {
  LucidAuthenticatable,
  LucidUserProviderOptions,
  DatabaseUserProviderOptions,
} from '../core/types.js'

/**
 * Config resolved by the "defineConfig" method
 */
export type ResolvedAuthConfig<
  KnownGuards extends Record<string, GuardFactory | GuardConfigProvider<GuardFactory>>,
> = {
  default: keyof KnownGuards
  loginRoute: string
  guards: {
    [K in keyof KnownGuards]: KnownGuards[K] extends GuardConfigProvider<infer A>
      ? A
      : KnownGuards[K]
  }
}

/**
 * Define configuration for the auth package. The function returns
 * a config provider that is invoked inside the auth service
 * provider
 */
export function defineConfig<
  KnownGuards extends Record<string, GuardFactory | GuardConfigProvider<GuardFactory>>,
>(config: {
  default: keyof KnownGuards
  loginRoute: string
  guards: KnownGuards
}): ConfigProvider<ResolvedAuthConfig<KnownGuards>> {
  return configProvider.create(async (app) => {
    const guardsList = Object.keys(config.guards)
    const guards = {} as Record<string, GuardFactory>

    for (let guardName of guardsList) {
      const guard = config.guards[guardName]
      if (typeof guard === 'function') {
        guards[guardName] = guard
      } else {
        guards[guardName] = await guard.resolver(guardName, app)
      }
    }

    return {
      default: config.default,
      loginRoute: config.loginRoute,
      guards: guards,
    } as ResolvedAuthConfig<KnownGuards>
  })
}

/**
 * Providers helper to configure user providers for
 * finding users for authentication
 */
export const providers: {
  db: <RealUser extends Record<string, any>>(
    config: DatabaseUserProviderOptions<RealUser>
  ) => ConfigProvider<DatabaseUserProvider<RealUser>>
  lucid: <RealUser extends LucidAuthenticatable>(
    config: LucidUserProviderOptions<RealUser>
  ) => ConfigProvider<LucidUserProvider<RealUser>>
} = {
  db(config) {
    return configProvider.create(async (app) => {
      const db = await app.container.make('lucid.db')
      const hasher = await app.container.make('hash')
      const { DatabaseUserProvider } = await import('./user_providers/main.js')
      return new DatabaseUserProvider(db, hasher.use(), config)
    })
  },
  lucid(config) {
    return configProvider.create(async () => {
      const { LucidUserProvider } = await import('./user_providers/main.js')
      return new LucidUserProvider(config)
    })
  },
}

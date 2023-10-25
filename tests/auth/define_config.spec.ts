/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { ApplicationService } from '@adonisjs/core/types'
import { AppFactory } from '@adonisjs/core/factories/app'
import { HttpContextFactory } from '@adonisjs/core/factories/http'
import { HashManagerFactory } from '@adonisjs/core/factories/hash'

import { createDatabase, createEmitter } from '../helpers.js'
import { AuthManager } from '../../src/auth/auth_manager.js'
import { Authenticator } from '../../src/auth/authenticator.js'
import { FactoryUser } from '../../factories/lucid_user_provider.js'
import { sessionGuard } from '../../src/guards/session/define_config.js'
import { defineConfig, providers } from '../../src/auth/define_config.js'
import { DatabaseUserProvider, LucidUserProvider } from '../../src/auth/user_providers/main.js'

const BASE_URL = new URL('./', import.meta.url)
const app = new AppFactory().create(BASE_URL, () => {}) as ApplicationService
await app.init()

test.group('Define config | providers', () => {
  test('configure lucid provider', async ({ assert }) => {
    const lucidConfigProvider = providers.lucid({
      model: async () => {
        return {
          default: FactoryUser,
        }
      },
      uids: ['email'],
    })

    const lucidProvider = await lucidConfigProvider.resolver(app)
    assert.instanceOf(lucidProvider, LucidUserProvider)
  })

  test('configure db provider', async ({ assert }) => {
    const dbConfigProvider = providers.db({
      table: 'users',
      id: 'id',
      passwordColumnName: 'password',
      uids: ['email'],
    })

    app.container.bind('lucid.db', () => createDatabase())
    app.container.bind('hash', () => new HashManagerFactory().create())

    const dbProvider = await dbConfigProvider.resolver(app)
    assert.instanceOf(dbProvider, DatabaseUserProvider)
  })
})

test.group('Define config', () => {
  test('define config for auth manager', async ({ assert }) => {
    const lucidConfigProvider = providers.lucid({
      model: async () => {
        return {
          default: FactoryUser,
        }
      },
      uids: ['email'],
    })

    const authConfigProvider = defineConfig({
      default: 'web',
      loginRoute: '/login',
      guards: {
        web: sessionGuard({
          provider: lucidConfigProvider,
        }),
      },
    })

    app.container.bind('emitter', () => createEmitter() as any)

    const authConfig = await authConfigProvider.resolver(app)
    const authManager = new AuthManager(authConfig)
    assert.instanceOf(authManager, AuthManager)
  })

  test('create auth object from auth manager', async ({ assert, expectTypeOf }) => {
    const lucidConfigProvider = providers.lucid({
      model: async () => {
        return {
          default: FactoryUser,
        }
      },
      uids: ['email'],
    })

    const authConfigProvider = defineConfig({
      default: 'web',
      loginRoute: '/login',
      guards: {
        web: sessionGuard({
          provider: lucidConfigProvider,
        }),
      },
    })

    app.container.bind('emitter', () => createEmitter() as any)

    const ctx = new HttpContextFactory().create()
    const authConfig = await authConfigProvider.resolver(app)
    const authManager = new AuthManager(authConfig)
    const auth = authManager.createAuthenticator(ctx)

    assert.instanceOf(auth, Authenticator)
    expectTypeOf(auth.use).parameters.toMatchTypeOf<['web'?]>()
  })
})

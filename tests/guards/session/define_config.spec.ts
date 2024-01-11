/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { AppFactory } from '@adonisjs/core/factories/app'
import { ApplicationService } from '@adonisjs/core/types'
import { HttpContextFactory } from '@adonisjs/core/factories/http'
import { HashManagerFactory } from '@adonisjs/core/factories/hash'

import { providers } from '../../../index.js'
import { createDatabase, createEmitter } from '../../helpers.js'
import { SessionGuard } from '../../../src/guards/session/guard.js'
import { FactoryUser } from '../../../factories/core/lucid_user_provider.js'
import { LucidUserProvider } from '../../../src/auth/user_providers/main.js'
import { sessionGuard, tokensProvider } from '../../../src/guards/session/define_config.js'

const BASE_URL = new URL('./', import.meta.url)
const app = new AppFactory().create(BASE_URL, () => {}) as ApplicationService
await app.init()

test.group('sessionGuard', () => {
  test('configure session guard', async ({ assert, expectTypeOf }) => {
    const sessionGuardProvider = sessionGuard({
      provider: providers.lucid({
        model: async () => {
          return {
            default: FactoryUser,
          }
        },
        passwordColumnName: 'password',
        uids: ['email'],
      }),
    })

    app.container.bind('emitter', () => createEmitter() as any)
    app.container.bind('hash', () => new HashManagerFactory().create())

    const sessionFactory = await sessionGuardProvider.resolver('web', app)
    assert.isFunction(sessionFactory)
    expectTypeOf(sessionFactory).returns.toMatchTypeOf<
      SessionGuard<LucidUserProvider<typeof FactoryUser>>
    >()

    const ctx = new HttpContextFactory().create()
    assert.instanceOf(sessionFactory(ctx), SessionGuard)
  })

  test('throw error when no provider is provided', async () => {
    await sessionGuard({} as any).resolver('web', app)
  }).throws('Invalid user provider defined on "web" guard')

  test('configure session guard with tokens provider', async ({ assert, expectTypeOf }) => {
    const sessionGuardProvider = sessionGuard({
      provider: providers.lucid({
        model: async () => {
          return {
            default: FactoryUser,
          }
        },
        passwordColumnName: 'password',
        uids: ['email'],
      }),
      tokens: tokensProvider.db({
        table: 'remember_me_tokens',
      }),
    })

    app.container.bind('emitter', () => createEmitter() as any)
    app.container.bind('lucid.db', () => createDatabase())
    app.container.bind('hash', () => new HashManagerFactory().create())

    const sessionFactory = await sessionGuardProvider.resolver('web', app)
    assert.isFunction(sessionFactory)
    expectTypeOf(sessionFactory).returns.toMatchTypeOf<
      SessionGuard<LucidUserProvider<typeof FactoryUser>>
    >()

    const ctx = new HttpContextFactory().create()
    assert.instanceOf(sessionFactory(ctx), SessionGuard)
  })
})

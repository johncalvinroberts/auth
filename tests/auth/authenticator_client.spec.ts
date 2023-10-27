/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { HttpContextFactory } from '@adonisjs/core/factories/http'

import { FactoryUser } from '../../factories/lucid_user_provider.js'
import { createDatabase, createEmitter, createTables } from '../helpers.js'
import { SessionGuardFactory } from '../../factories/session_guard_factory.js'
import { AuthenticatorClient } from '../../src/auth/authenticator_client.js'

test.group('Authenticator client', () => {
  test('create authenticator client with guards', async ({ assert, expectTypeOf }) => {
    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const sessionGuard = new SessionGuardFactory().create(ctx).withEmitter(emitter)

    const client = new AuthenticatorClient({
      default: 'web',
      guards: {
        web: () => sessionGuard,
      },
    })

    assert.instanceOf(client, AuthenticatorClient)
    expectTypeOf(client.use).parameters.toMatchTypeOf<['web'?]>()
  })

  test('access guard using its name', async ({ assert, expectTypeOf }) => {
    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const sessionGuard = new SessionGuardFactory().create(ctx).withEmitter(emitter)

    const client = new AuthenticatorClient({
      default: 'web',
      guards: {
        web: () => sessionGuard,
      },
    })

    const webGuard = client.use('web')
    assert.strictEqual(webGuard, sessionGuard)
    assert.equal(client.defaultGuard, 'web')
    assert.equal(webGuard.driverName, 'session')
    assert.strictEqual(client.use('web'), client.use('web'))
    assert.strictEqual(client.use(), client.use('web'))
    expectTypeOf(webGuard.user).toMatchTypeOf<FactoryUser | undefined>()
  })

  test('call authenticateAsClient via client', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const user = await FactoryUser.createWithDefaults()
    const sessionGuard = new SessionGuardFactory().create(ctx).withEmitter(emitter)

    const client = new AuthenticatorClient({
      default: 'web',
      guards: {
        web: () => sessionGuard,
      },
    })

    assert.deepEqual(await client.use('web').authenticateAsClient(user), {
      session: {
        auth_web: user.id,
      },
    })
  })
})

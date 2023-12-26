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
import { SessionMiddlewareFactory } from '@adonisjs/session/factories'

import { Authenticator } from '../../src/auth/authenticator.js'
import { FactoryUser } from '../../factories/lucid_user_provider.js'
import { createDatabase, createEmitter, createTables } from '../helpers.js'
import { SessionGuardFactory } from '../../factories/session_guard_factory.js'

test.group('Authenticator', () => {
  test('create authenticator with guards', async ({ assert, expectTypeOf }) => {
    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const sessionGuard = new SessionGuardFactory().create(ctx).setEmitter(emitter)

    const authenticator = new Authenticator(ctx, {
      default: 'web',
      guards: {
        web: () => sessionGuard,
      },
    })

    assert.instanceOf(authenticator, Authenticator)
    expectTypeOf(authenticator.use).parameters.toMatchTypeOf<['web'?]>()
  })

  test('access guard using its name', async ({ assert, expectTypeOf }) => {
    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const sessionGuard = new SessionGuardFactory().create(ctx).setEmitter(emitter)

    const authenticator = new Authenticator(ctx, {
      default: 'web',
      guards: {
        web: () => sessionGuard,
      },
    })

    const webGuard = authenticator.use('web')
    assert.strictEqual(webGuard, sessionGuard)
    assert.equal(authenticator.defaultGuard, 'web')
    assert.equal(webGuard.driverName, 'session')
    assert.strictEqual(authenticator.use('web'), authenticator.use('web'))
    expectTypeOf(webGuard.user).toMatchTypeOf<FactoryUser | undefined>()
  })

  test('authenticate using the default guard', async ({ assert, expectTypeOf }) => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const user = await FactoryUser.createWithDefaults()
    const sessionGuard = new SessionGuardFactory().create(ctx).setEmitter(emitter)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    const authenticator = new Authenticator(ctx, {
      default: 'web',
      guards: {
        web: () => sessionGuard,
      },
    })

    await sessionMiddleware.handle(ctx, async () => {
      ctx.session.put('auth_web', user.id)
      await authenticator.authenticateUsing()
    })

    assert.instanceOf(authenticator.user, FactoryUser)
    assert.equal(authenticator.user!.id, user.id)
    expectTypeOf(authenticator.user).toMatchTypeOf<FactoryUser | undefined>()
    expectTypeOf(authenticator.getUserOrFail()).toMatchTypeOf<FactoryUser>()
    assert.equal(authenticator.authenticatedViaGuard, 'web')
    assert.isTrue(authenticator.isAuthenticated)
    assert.isTrue(authenticator.authenticationAttempted)
  })

  test('throw error when unable to authenticate', async ({ assert }) => {
    assert.plan(4)

    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const sessionGuard = new SessionGuardFactory().create(ctx).setEmitter(emitter)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    const authenticator = new Authenticator(ctx, {
      default: 'web',
      guards: {
        web: () => sessionGuard,
      },
    })

    try {
      await sessionMiddleware.handle(ctx, async () => {
        await authenticator.authenticateUsing()
      })
    } catch (error) {
      assert.equal(error.message, 'Unauthorized access')
      assert.equal(error.guardDriverName, 'session')
    }

    assert.isFalse(authenticator.isAuthenticated)
    assert.isTrue(authenticator.authenticationAttempted)
  })
})

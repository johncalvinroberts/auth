/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { Scrypt } from '@adonisjs/core/hash/drivers/scrypt'
import { HttpContextFactory } from '@adonisjs/core/factories/http'
import { SessionMiddlewareFactory } from '@adonisjs/session/factories'

import { FactoryUser } from '../../../factories/core/lucid_user_provider.js'
import { SessionGuardFactory } from '../../../factories/guards/session/guard_factory.js'
import { createDatabase, createEmitter, createTables, pEvent } from '../../helpers.js'

test.group('Session guard | loginViaId', () => {
  test('login user via id', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const user = await FactoryUser.createWithDefaults({
      password: await new Scrypt({}).make('secret'),
    })
    const sessionGuard = new SessionGuardFactory().create(ctx, emitter)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    await Promise.all([
      sessionMiddleware.handle(ctx, async () => {
        await sessionGuard.loginViaId(user.id)
      }),
    ])

    assert.equal(sessionGuard.user!.id, user.id)
    // since the attempt method will fetch from db
    assert.notStrictEqual(sessionGuard.user, user)
    assert.isFalse(sessionGuard.isLoggedOut)
    assert.isFalse(sessionGuard.isAuthenticated)
    assert.isFalse(sessionGuard.authenticationAttempted)
    assert.deepEqual(ctx.session.all(), { auth_web: user.id })
  })

  test('throw error when user for the id does not exists', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const sessionGuard = new SessionGuardFactory().create(ctx, emitter)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    const [loginFailed, attemptResult] = await Promise.allSettled([
      pEvent(emitter, 'session_auth:login_failed'),
      sessionMiddleware.handle(ctx, async () => {
        await sessionGuard.loginViaId(1)
      }),
    ])

    assert.equal(attemptResult.status, 'rejected')
    assert.equal(loginFailed.status, 'fulfilled')
    if (attemptResult.status === 'rejected') {
      assert.equal(attemptResult.reason.message, 'Invalid credentials')
    }
  })
})

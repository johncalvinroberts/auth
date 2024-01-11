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
import { SessionGuardFactory } from '../../../factories/session_guard_factory.js'
import { createDatabase, createEmitter, createTables, pEvent } from '../../helpers.js'

test.group('Session guard | attempt', () => {
  test('login user using email and password', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const user = await FactoryUser.createWithDefaults({
      password: await new Scrypt({}).make('secret'),
    })

    const sessionGuard = new SessionGuardFactory().create(ctx, emitter)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    const [credentialsVerified] = await Promise.all([
      pEvent(emitter, 'session_auth:credentials_verified'),
      sessionMiddleware.handle(ctx, async () => {
        await sessionGuard.attempt(user.email, 'secret')
      }),
    ])

    assert.strictEqual(credentialsVerified?.user, sessionGuard.user)
    assert.equal(credentialsVerified?.uid, sessionGuard.user!.email)
    assert.equal(sessionGuard.user!.id, user.id)

    /**
     * since the attempt method will fetch user from db, the local
     * and refetched instances will be different
     */
    assert.notStrictEqual(sessionGuard.user, user)

    assert.isFalse(sessionGuard.isLoggedOut)
    assert.isFalse(sessionGuard.isAuthenticated)
    assert.isFalse(sessionGuard.authenticationAttempted)
    assert.deepEqual(ctx.session.all(), { auth_web: user.id })
  })

  test('throw error when password is invalid', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const user = await FactoryUser.createWithDefaults({
      password: await new Scrypt({}).make('secret'),
    })
    const sessionGuard = new SessionGuardFactory().create(ctx, emitter)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    const [loginFailed, attemptResult] = await Promise.allSettled([
      pEvent(emitter, 'session_auth:login_failed'),
      sessionMiddleware.handle(ctx, async () => {
        await sessionGuard.attempt(user.email, 'foo')
      }),
    ])

    assert.equal(attemptResult.status, 'rejected')
    assert.equal(loginFailed.status, 'fulfilled')
    if (attemptResult.status === 'rejected') {
      assert.equal(attemptResult.reason.message, 'Invalid credentials')
    }
  })

  test('throw error when unable to find the user by uid', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const sessionGuard = new SessionGuardFactory().create(ctx, emitter)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    const [loginFailed, attemptResult] = await Promise.allSettled([
      pEvent(emitter, 'session_auth:login_failed'),
      sessionMiddleware.handle(ctx, async () => {
        await sessionGuard.attempt('foo', 'foo')
      }),
    ])

    assert.equal(attemptResult.status, 'rejected')
    assert.equal(loginFailed.status, 'fulfilled')
    if (attemptResult.status === 'rejected') {
      assert.equal(attemptResult.reason.message, 'Invalid credentials')
    }
  })
})

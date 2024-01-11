/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { SessionMiddlewareFactory } from '@adonisjs/session/factories'
import { HttpContextFactory } from '@adonisjs/core/factories/http'

import { FactoryUser } from '../../../factories/core/lucid_user_provider.js'
import { RememberMeToken } from '../../../src/guards/session/remember_me_token.js'
import { SessionGuardFactory } from '../../../factories/session_guard_factory.js'
import {
  pEvent,
  createTables,
  parseCookies,
  createEmitter,
  createDatabase,
  defineCookies,
} from '../../helpers.js'
import { DatabaseRememberTokenProvider } from '../../../src/guards/session/token_providers/database.js'

test.group('Session guard | logout', () => {
  test('logout user by deleting auth data from session store', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const user = await FactoryUser.createWithDefaults()
    const sessionGuard = new SessionGuardFactory().create(ctx, emitter)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    await sessionMiddleware.handle(ctx, async () => {
      await sessionGuard.login(user)
    })

    assert.strictEqual(sessionGuard.user, user)
    assert.isFalse(sessionGuard.isLoggedOut)
    assert.isFalse(sessionGuard.isAuthenticated)
    assert.isFalse(sessionGuard.authenticationAttempted)
    assert.deepEqual(ctx.session.all(), { auth_web: user.id })

    /**
     * Logging out
     */
    await sessionGuard.logout()
    assert.deepEqual(ctx.session.all(), {})
  })

  test('logout user by deleting remember me token and cookie', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const tokensProvider = new DatabaseRememberTokenProvider(db, { table: 'remember_me_tokens' })
    const user = await FactoryUser.createWithDefaults()
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    const token = RememberMeToken.create(user.id, '1 year', 'web')
    await tokensProvider.createToken(token)

    const ctx = new HttpContextFactory().create()

    ctx.request.request.headers.cookie = defineCookies([
      {
        key: 'remember_web',
        value: token.value!.release(),
        type: 'encrypted',
      },
    ])

    const sessionGuard = new SessionGuardFactory()
      .create(ctx, emitter)
      .withRememberMeTokens(tokensProvider)

    await sessionMiddleware.handle(ctx, async () => {
      await sessionGuard.logout()
    })

    assert.deepEqual(ctx.session.all(), {})

    const cookies = parseCookies(ctx.response.getHeader('set-cookie') as string[])
    assert.property(cookies, 'remember_web')
    assert.equal(cookies.remember_web.maxAge, -1)
    assert.equal(cookies.remember_web.httpOnly, true)

    const persistedToken = await tokensProvider.getTokenBySeries(token.series)
    assert.isNull(persistedToken)
  })

  test('emit logged_out event', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const user = await FactoryUser.createWithDefaults()
    const sessionGuard = new SessionGuardFactory().create(ctx, emitter)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    await sessionMiddleware.handle(ctx, async () => {
      await sessionGuard.login(user)
    })

    assert.strictEqual(sessionGuard.user, user)
    assert.isFalse(sessionGuard.isLoggedOut)
    assert.isFalse(sessionGuard.isAuthenticated)
    assert.isFalse(sessionGuard.authenticationAttempted)
    assert.deepEqual(ctx.session.all(), { auth_web: user.id })

    /**
     * Logging out
     */

    const [loggedOut] = await Promise.all([
      pEvent(emitter, 'session_auth:logged_out'),
      sessionGuard.logout(),
    ])

    assert.deepEqual(loggedOut!.user, sessionGuard.user)
    assert.equal(loggedOut!.sessionId, ctx.session.sessionId)
    assert.deepEqual(ctx.session.all(), {})
  })

  test('silently ignore invalid remember me token', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const tokensProvider = new DatabaseRememberTokenProvider(db, { table: 'remember_me_tokens' })
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    const ctx = new HttpContextFactory().create()
    ctx.request.request.headers.cookie = defineCookies([
      {
        key: 'remember_web',
        value: 'foo',
        type: 'encrypted',
      },
    ])

    const sessionGuard = new SessionGuardFactory()
      .create(ctx, emitter)
      .withRememberMeTokens(tokensProvider)
    await sessionMiddleware.handle(ctx, async () => {
      await sessionGuard.logout()
    })

    assert.deepEqual(ctx.session.all(), {})

    const cookies = parseCookies(ctx.response.getHeader('set-cookie') as string[])
    assert.property(cookies, 'remember_web')
    assert.equal(cookies.remember_web.maxAge, -1)
    assert.equal(cookies.remember_web.httpOnly, true)
  })
})

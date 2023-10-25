/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Socket } from 'node:net'
import { test } from '@japa/runner'
import { IncomingMessage } from 'node:http'
import { CookieClient } from '@adonisjs/core/http'
import { SessionMiddlewareFactory } from '@adonisjs/session/factories'
import { HttpContextFactory, RequestFactory } from '@adonisjs/core/factories/http'

import { RememberMeToken } from '../../../src/guards/session/token.js'
import { FactoryUser } from '../../../factories/lucid_user_provider.js'
import { SessionGuardFactory } from '../../../factories/session_guard_factory.js'
import {
  pEvent,
  encryption,
  createTables,
  parseCookies,
  createEmitter,
  createDatabase,
} from '../../helpers.js'
import { DatabaseRememberTokenProvider } from '../../../src/guards/session/token_providers/main.js'

test.group('Session guard | logout', () => {
  test('logout user by deleting auth data from session store', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const ctx = new HttpContextFactory().create()
    const user = await FactoryUser.createWithDefaults()
    const sessionGuard = new SessionGuardFactory().create(ctx)
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

    const tokensProvider = new DatabaseRememberTokenProvider(db, { table: 'remember_me_tokens' })
    const user = await FactoryUser.createWithDefaults()
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    const token = RememberMeToken.create(user.id, '1 year')
    await tokensProvider.createToken(token)

    const client = new CookieClient(encryption)
    const req = new IncomingMessage(new Socket())
    req.headers['cookie'] = `remember_web=${client.encrypt('remember_web', token.value)};`

    const ctx = new HttpContextFactory()
      .merge({
        request: new RequestFactory()
          .merge({
            req,
          })
          .create(),
      })
      .create()

    const sessionGuard = new SessionGuardFactory().create(ctx).withRememberMeTokens(tokensProvider)
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

    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const user = await FactoryUser.createWithDefaults()
    const sessionGuard = new SessionGuardFactory().create(ctx).withEmitter(emitter)
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

    const tokensProvider = new DatabaseRememberTokenProvider(db, { table: 'remember_me_tokens' })
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    const client = new CookieClient(encryption)
    const req = new IncomingMessage(new Socket())
    req.headers['cookie'] = `remember_web=${client.encrypt('remember_web', 'foo')};`

    const ctx = new HttpContextFactory()
      .merge({
        request: new RequestFactory()
          .merge({
            req,
          })
          .create(),
      })
      .create()

    const sessionGuard = new SessionGuardFactory().create(ctx).withRememberMeTokens(tokensProvider)
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

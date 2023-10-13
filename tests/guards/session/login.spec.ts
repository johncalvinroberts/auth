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

import { RememberMeToken } from '../../../src/session/token.js'
import { FactoryUser } from '../../../factories/lucid_user_provider.js'
import { SessionGuardFactory } from '../../../factories/session_guard_factory.js'
import { DatabaseRememberTokenProvider } from '../../../src/session/token_providers/main.js'
import { createDatabase, createEmitter, createTables, pEvent, parseCookies } from '../../helpers.js'

test.group('Session guard | login', () => {
  test('login a user using the user object', async ({ assert }) => {
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
  })

  test('emit events around user login', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const user = await FactoryUser.createWithDefaults()
    const sessionGuard = new SessionGuardFactory().create(ctx).withEmitter(emitter)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    const [loginAttempted, loginSucceeded] = await Promise.all([
      pEvent(emitter, 'session_auth:login_attempted'),
      pEvent(emitter, 'session_auth:login_succeeded'),
      sessionMiddleware.handle(ctx, async () => {
        await sessionGuard.login(user)
      }),
    ])

    assert.strictEqual(loginAttempted!.user, user)
    assert.strictEqual(loginSucceeded!.user, user)
    assert.equal(loginSucceeded!.sessionId, ctx.session.sessionId)
    assert.isUndefined(loginSucceeded!.rememberMeToken)
  })

  test('create remember me cookie', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const ctx = new HttpContextFactory().create()
    const tokensProvider = new DatabaseRememberTokenProvider(db, { table: 'remember_me_tokens' })
    const user = await FactoryUser.createWithDefaults()
    const sessionGuard = new SessionGuardFactory().create(ctx).withRememberMeTokens(tokensProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    await sessionMiddleware.handle(ctx, async () => {
      await sessionGuard.login(user, true)
    })

    assert.strictEqual(sessionGuard.user, user)
    assert.isFalse(sessionGuard.isLoggedOut)
    assert.isFalse(sessionGuard.isAuthenticated)
    assert.isFalse(sessionGuard.authenticationAttempted)
    assert.deepEqual(ctx.session.all(), { auth_web: user.id })

    /**
     * Parsing response cookies
     */
    const cookies = parseCookies(ctx.response.getHeader('set-cookie') as string[])
    assert.property(cookies, 'remember_web')
    assert.equal(cookies.remember_web.maxAge, 157788000)
    assert.equal(cookies.remember_web.httpOnly, true)

    /**
     * Ensure the remember me cookie can be decoded by
     * the server
     */
    const decodedToken = RememberMeToken.decode(cookies.remember_web.value)
    assert.properties(decodedToken, ['series', 'value'])

    /**
     * Verifying the cookie exists in the database
     */
    const persistedToken = await tokensProvider.getTokenBySeries(decodedToken.series)
    assert.exists(persistedToken)
    assert.isTrue(persistedToken!.verify(decodedToken.value))
  })

  test('throw error when trying to create remember_me token with tokens provider', async () => {
    const db = await createDatabase()
    await createTables(db)

    const ctx = new HttpContextFactory().create()
    const user = await FactoryUser.createWithDefaults()
    const sessionGuard = new SessionGuardFactory().create(ctx)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    await sessionMiddleware.handle(ctx, async () => {
      await sessionGuard.login(user, true)
    })
  }).throws(
    'Cannot use "rememberMe" feature. Please configure the tokens provider inside config/auth file'
  )

  test('throw error when trying to use session guard without session middleware', async () => {
    const db = await createDatabase()
    await createTables(db)

    const ctx = new HttpContextFactory().create()
    const user = await FactoryUser.createWithDefaults()
    const sessionGuard = new SessionGuardFactory().create(ctx)

    await sessionGuard.login(user)
  }).throws(
    'Cannot login user. Make sure you have installed the "@adonisjs/session" package and configured its middleware'
  )
})

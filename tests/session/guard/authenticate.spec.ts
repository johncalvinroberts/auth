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

import { createEmitter, defineCookies, timeTravel } from '../../helpers.js'
import { E_UNAUTHORIZED_ACCESS } from '../../../src/errors.js'
import { SessionGuard } from '../../../modules/session_guard/guard.js'
import { SessionFakeUserProvider } from '../../../factories/session_guard/main.js'
import { RememberMeToken } from '../../../modules/session_guard/remember_me_token.js'

test.group('Session guard | authenticate | via session', () => {
  test('mark user as logged-in when a valid session exists', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    const user = await sessionMiddleware.handle(ctx, () => {
      ctx.session.put('auth_web', 1) // setting auth state for userId 1
      return guard.authenticate()
    })

    assert.isTrue(guard.authenticationAttempted)
    assert.isTrue(guard.isAuthenticated)
    assert.isDefined(guard.user)
    assert.deepEqual(guard.user, user)
    assert.deepEqual(guard.user, { id: 1, email: 'virk@adonisjs.com', password: 'secret' })
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.viaRemember)
  })

  test('throw error when session does not exist', async ({ assert }) => {
    assert.plan(8)

    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    try {
      await sessionMiddleware.handle(ctx, () => {
        return guard.authenticate()
      })
    } catch (error) {
      assert.instanceOf(error, E_UNAUTHORIZED_ACCESS)
      assert.equal(error.message, 'Invalid or expired user session')
      assert.equal(error.guardDriverName, 'session')
    }

    assert.isTrue(guard.authenticationAttempted)
    assert.isFalse(guard.isAuthenticated)
    assert.isUndefined(guard.user)
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.viaRemember)
  })

  test('throw error when user does not exist', async ({ assert }) => {
    assert.plan(8)

    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    try {
      await sessionMiddleware.handle(ctx, () => {
        ctx.session.put('auth_web', 10) // there is no user with id 10
        return guard.authenticate()
      })
    } catch (error) {
      assert.instanceOf(error, E_UNAUTHORIZED_ACCESS)
      assert.equal(error.message, 'Invalid or expired user session')
      assert.equal(error.guardDriverName, 'session')
    }

    assert.isTrue(guard.authenticationAttempted)
    assert.isFalse(guard.isAuthenticated)
    assert.isUndefined(guard.user)
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.viaRemember)
  })
})

test.group('Session guard | authenticate | via remember me cookie', () => {
  test('create user session and mark them as logged-in via remember cookie', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const token = RememberMeToken.create(1, '20 mins')

    const originalExpiryTime = token.expiresAt.getTime()
    const originalUpdatedAtTime = token.updatedAt.getTime()
    const originalHash = token.hash
    const originalSeries = token.series

    userProvider.useToken(token)
    ctx.request.request.headers.cookie = defineCookies([
      {
        key: 'remember_web',
        value: token.value!.release(),
        type: 'encrypted',
      },
    ])

    const user = await sessionMiddleware.handle(ctx, () => {
      return guard.authenticate()
    })

    assert.isTrue(guard.authenticationAttempted)
    assert.isTrue(guard.isAuthenticated)
    assert.isDefined(guard.user)
    assert.deepEqual(guard.user, user)
    assert.deepEqual(guard.user, { id: 1, email: 'virk@adonisjs.com', password: 'secret' })
    assert.isFalse(guard.isLoggedOut)
    assert.isTrue(guard.viaRemember)
    assert.deepEqual(ctx.session.all(), { auth_web: user.id })

    assert.equal(token.expiresAt.getTime(), originalExpiryTime)
    assert.equal(token.updatedAt.getTime(), originalUpdatedAtTime)
    assert.equal(token.hash, originalHash)
    assert.equal(token.series, originalSeries)
  })

  test('recycle token when the existing token is older than 1 minute', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const token = RememberMeToken.create(1, '20 mins')
    const originalExpiryTime = token.expiresAt.getTime()
    const originalUpdatedAtTime = token.updatedAt.getTime()
    const originalHash = token.hash
    const originalSeries = token.series

    userProvider.useToken(token)
    timeTravel(120)

    ctx.request.request.headers.cookie = defineCookies([
      {
        key: 'remember_web',
        value: token.value!.release(),
        type: 'encrypted',
      },
    ])

    const user = await sessionMiddleware.handle(ctx, () => {
      return guard.authenticate()
    })

    assert.isTrue(guard.authenticationAttempted)
    assert.isTrue(guard.isAuthenticated)
    assert.isDefined(guard.user)
    assert.deepEqual(guard.user, user)
    assert.deepEqual(guard.user, { id: 1, email: 'virk@adonisjs.com', password: 'secret' })
    assert.isFalse(guard.isLoggedOut)
    assert.isTrue(guard.viaRemember)
    assert.deepEqual(ctx.session.all(), { auth_web: user.id })

    assert.isAbove(token.expiresAt.getTime(), originalExpiryTime)
    assert.isAbove(token.updatedAt.getTime(), originalUpdatedAtTime)
    assert.notEqual(token.hash, originalHash)
    assert.equal(token.series, originalSeries)
  })

  test('throw error when token has been expired', async ({ assert }) => {
    assert.plan(9)

    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const token = RememberMeToken.create(1, '20 mins')

    userProvider.useToken(token)
    timeTravel(21 * 60)

    ctx.request.request.headers.cookie = defineCookies([
      {
        key: 'remember_web',
        value: token.value!.release(),
        type: 'encrypted',
      },
    ])

    try {
      await sessionMiddleware.handle(ctx, () => {
        return guard.authenticate()
      })
    } catch (error) {
      assert.instanceOf(error, E_UNAUTHORIZED_ACCESS)
      assert.equal(error.message, 'Invalid or expired user session')
      assert.equal(error.guardDriverName, 'session')
    }

    assert.isTrue(guard.authenticationAttempted)
    assert.isFalse(guard.isAuthenticated)
    assert.isUndefined(guard.user)
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.viaRemember)
    assert.deepEqual(ctx.session.all(), {})
  })

  test('throw error when token does not exist', async ({ assert }) => {
    assert.plan(9)

    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const token = RememberMeToken.create(1, '20 mins')

    ctx.request.request.headers.cookie = defineCookies([
      {
        key: 'remember_web',
        value: token.value!.release(),
        type: 'encrypted',
      },
    ])

    try {
      await sessionMiddleware.handle(ctx, () => {
        return guard.authenticate()
      })
    } catch (error) {
      assert.instanceOf(error, E_UNAUTHORIZED_ACCESS)
      assert.equal(error.message, 'Invalid or expired user session')
      assert.equal(error.guardDriverName, 'session')
    }

    assert.isTrue(guard.authenticationAttempted)
    assert.isFalse(guard.isAuthenticated)
    assert.isUndefined(guard.user)
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.viaRemember)
    assert.deepEqual(ctx.session.all(), {})
  })

  test('throw error when remember me cookie does exist', async ({ assert }) => {
    assert.plan(9)

    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const token = RememberMeToken.create(1, '20 mins')
    userProvider.useToken(token)

    try {
      await sessionMiddleware.handle(ctx, () => {
        return guard.authenticate()
      })
    } catch (error) {
      assert.instanceOf(error, E_UNAUTHORIZED_ACCESS)
      assert.equal(error.message, 'Invalid or expired user session')
      assert.equal(error.guardDriverName, 'session')
    }

    assert.isTrue(guard.authenticationAttempted)
    assert.isFalse(guard.isAuthenticated)
    assert.isUndefined(guard.user)
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.viaRemember)
    assert.deepEqual(ctx.session.all(), {})
  })

  test('throw error when token is malformed', async ({ assert }) => {
    assert.plan(9)

    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const token = RememberMeToken.create(1, '20 mins')

    userProvider.useToken(token)

    ctx.request.request.headers.cookie = defineCookies([
      {
        key: 'remember_web',
        value: 'foo',
        type: 'encrypted',
      },
    ])

    try {
      await sessionMiddleware.handle(ctx, () => {
        return guard.authenticate()
      })
    } catch (error) {
      assert.instanceOf(error, E_UNAUTHORIZED_ACCESS)
      assert.equal(error.message, 'Invalid or expired user session')
      assert.equal(error.guardDriverName, 'session')
    }

    assert.isTrue(guard.authenticationAttempted)
    assert.isFalse(guard.isAuthenticated)
    assert.isUndefined(guard.user)
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.viaRemember)
    assert.deepEqual(ctx.session.all(), {})
  })

  test('throw error when user does not exist', async ({ assert }) => {
    assert.plan(9)

    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const token = RememberMeToken.create(10, '20 mins')
    userProvider.useToken(token)

    ctx.request.request.headers.cookie = defineCookies([
      {
        key: 'remember_web',
        value: token.value!.release(),
        type: 'encrypted',
      },
    ])

    try {
      await sessionMiddleware.handle(ctx, () => {
        return guard.authenticate()
      })
    } catch (error) {
      assert.instanceOf(error, E_UNAUTHORIZED_ACCESS)
      assert.equal(error.message, 'Invalid or expired user session')
      assert.equal(error.guardDriverName, 'session')
    }

    assert.isTrue(guard.authenticationAttempted)
    assert.isFalse(guard.isAuthenticated)
    assert.isUndefined(guard.user)
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.viaRemember)
    assert.deepEqual(ctx.session.all(), {})
  })
})

test.group('Session guard | authenticate | via session', () => {
  test('multiple calls to authenticate should be a noop', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    /**
     * Fails for the first time
     */
    await assert.rejects(() => guard.authenticate())

    /**
     * Then we setup the session
     */
    await sessionMiddleware.handle(ctx, () => {
      ctx.session.put('auth_web', 1)
    })

    /**
     * But still unauthenticated, because the method does not
     * re-form the authentication
     */
    await assert.rejects(() => guard.authenticate())

    assert.isTrue(guard.authenticationAttempted)
    assert.isFalse(guard.isAuthenticated)
    assert.isUndefined(guard.user)
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.viaRemember)
  })
})

test.group('Session guard | check', () => {
  test('return true when user is logged-in', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    const isLoggedIn = await sessionMiddleware.handle(ctx, () => {
      ctx.session.put('auth_web', 1) // setting auth state for userId 1
      return guard.check()
    })

    assert.isTrue(isLoggedIn)
    assert.isTrue(guard.authenticationAttempted)
    assert.isTrue(guard.isAuthenticated)
    assert.isDefined(guard.user)
    assert.deepEqual(guard.user, { id: 1, email: 'virk@adonisjs.com', password: 'secret' })
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.viaRemember)
  })

  test('return false when user is not logged-in', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    const isLoggedIn = await sessionMiddleware.handle(ctx, () => {
      return guard.check()
    })

    assert.isFalse(isLoggedIn)
    assert.isTrue(guard.authenticationAttempted)
    assert.isFalse(guard.isAuthenticated)
    assert.isUndefined(guard.user)
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.viaRemember)
  })

  test('re-throw errors other than the E_UNAUTHORIZED_ACCESS', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)

    await assert.rejects(
      () => guard.check(),
      'Cannot authenticate user. Install and configure "@adonisjs/session" package'
    )
  })
})

test.group('Session guard | getUserOrFail', () => {
  test('return user when user is logged-in', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    await sessionMiddleware.handle(ctx, () => {
      ctx.session.put('auth_web', 1) // setting auth state for userId 1
      return guard.authenticate()
    })

    assert.isTrue(guard.authenticationAttempted)
    assert.isTrue(guard.isAuthenticated)
    assert.deepEqual(guard.user, guard.getUserOrFail())
    assert.deepEqual(guard.getUserOrFail(), {
      id: 1,
      email: 'virk@adonisjs.com',
      password: 'secret',
    })
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.viaRemember)
  })

  test('throw error when user is not logged-in', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    assert.throws(() => guard.getUserOrFail(), 'Invalid or expired user session')
    await sessionMiddleware.handle(ctx, () => {
      return guard.check()
    })

    assert.throws(() => guard.getUserOrFail(), 'Invalid or expired user session')
  })
})

test.group('Session guard | authenticateAsClient', () => {
  test('return session state for client login', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    assert.deepEqual(
      await guard.authenticateAsClient((await userProvider.findById(1))!.getOriginal()),
      {
        session: {
          auth_web: 1,
        },
      }
    )
  })
})

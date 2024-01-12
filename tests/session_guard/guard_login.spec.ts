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

import { createEmitter, parseCookies } from '../helpers.js'
import { SessionGuard } from '../../modules/session_guard/guard.js'
import { SessionFakeUserProvider } from '../../factories/session_guard/main.js'
import { E_INVALID_CREDENTIALS } from '../../src/errors.js'

test.group('Session guard | login', () => {
  test('create session for the user', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const user = await userProvider.findById(1)

    await sessionMiddleware.handle(ctx, () => {
      return guard.login(user!.getOriginal())
    })

    assert.deepEqual(ctx.session.all(), { auth_web: 1 })
    assert.deepEqual(guard.user, user!.getOriginal())
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.isAuthenticated)
    assert.isFalse(guard.authenticationAttempted)
  })

  test('generate remember me token cookie', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const user = await userProvider.findById(1)

    await sessionMiddleware.handle(ctx, () => {
      return guard.login(user!.getOriginal(), true)
    })

    assert.containsSubset(parseCookies(ctx.response.getHeader('set-cookie') as string), {
      remember_web: {
        httpOnly: true,
        name: 'remember_web',
        path: '/',
        value: userProvider.getToken()!.value!.release(),
      },
    })
    assert.deepEqual(ctx.session.all(), { auth_web: 1 })
    assert.deepEqual(guard.user, user!.getOriginal())
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.isAuthenticated)
    assert.isFalse(guard.authenticationAttempted)
  })
})

test.group('Session guard | loginViaId', () => {
  test('create session for the user by id', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    await sessionMiddleware.handle(ctx, () => {
      return guard.loginViaId(1)
    })

    assert.deepEqual(ctx.session.all(), { auth_web: 1 })
    assert.deepEqual(guard.user, { email: 'virk@adonisjs.com', id: 1, password: 'secret' })
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.isAuthenticated)
    assert.isFalse(guard.authenticationAttempted)
  })

  test('throw error when user for the id does not exist', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    try {
      await sessionMiddleware.handle(ctx, () => {
        return guard.loginViaId(10)
      })
    } catch (error) {
      assert.instanceOf(error, E_INVALID_CREDENTIALS)
      assert.equal(error.message, 'Invalid user credentails')
      assert.equal(error.guardDriverName, 'session')
    }

    assert.deepEqual(ctx.session.all(), {})
    assert.isUndefined(guard.user)
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.isAuthenticated)
    assert.isFalse(guard.authenticationAttempted)
  })
})

test.group('Session guard | attempt', () => {
  test('create session for the user after verifying credentials', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    await sessionMiddleware.handle(ctx, () => {
      return guard.attempt('virk@adonisjs.com', 'secret')
    })

    assert.deepEqual(ctx.session.all(), { auth_web: 1 })
    assert.deepEqual(guard.user, { email: 'virk@adonisjs.com', id: 1, password: 'secret' })
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.isAuthenticated)
    assert.isFalse(guard.authenticationAttempted)
  })

  test('throw error when credentials are invalid', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    try {
      await sessionMiddleware.handle(ctx, () => {
        return guard.attempt('virk@adonisjs.com', 'foo')
      })
    } catch (error) {
      assert.instanceOf(error, E_INVALID_CREDENTIALS)
      assert.equal(error.message, 'Invalid user credentails')
      assert.equal(error.guardDriverName, 'session')
    }

    assert.deepEqual(ctx.session.all(), {})
    assert.isUndefined(guard.user)
    assert.isFalse(guard.isLoggedOut)
    assert.isFalse(guard.isAuthenticated)
    assert.isFalse(guard.authenticationAttempted)
  })
})

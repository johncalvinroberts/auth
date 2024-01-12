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

import { createEmitter, defineCookies, parseCookies } from '../../helpers.js'
import { SessionGuard } from '../../../modules/session_guard/guard.js'
import { SessionFakeUserProvider } from '../../../factories/session_guard/main.js'
import { RememberMeToken } from '../../../modules/session_guard/remember_me_token.js'

test.group('Session guard | logout', () => {
  test('delete user session', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new SessionFakeUserProvider()

    const guard = new SessionGuard('web', {}, ctx, emitter, userProvider)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    await sessionMiddleware.handle(ctx, () => {
      ctx.session.put('auth_web', 1)
      return guard.logout()
    })

    assert.deepEqual(ctx.session.all(), {})
    assert.containsSubset(parseCookies(ctx.response.getHeader('set-cookie') as string), {
      remember_web: {
        maxAge: -1,
        name: 'remember_web',
        value: '',
        expires: new Date(0),
      },
    })
    assert.isUndefined(guard.user)
    assert.isTrue(guard.isLoggedOut)
    assert.isFalse(guard.isAuthenticated)
    assert.isFalse(guard.authenticationAttempted)
    assert.isFalse(guard.viaRemember)
  })

  test('delete remember token when one exists', async ({ assert }) => {
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
        value: token.value!.release(),
        type: 'encrypted',
      },
    ])

    await sessionMiddleware.handle(ctx, () => {
      ctx.session.put('auth_web', 1)
      return guard.logout()
    })

    assert.deepEqual(ctx.session.all(), {})
    assert.containsSubset(parseCookies(ctx.response.getHeader('set-cookie') as string), {
      remember_web: {
        maxAge: -1,
        name: 'remember_web',
        value: '',
        expires: new Date(0),
      },
    })
    assert.isUndefined(guard.user)
    assert.isTrue(guard.isLoggedOut)
    assert.isFalse(guard.isAuthenticated)
    assert.isFalse(guard.authenticationAttempted)
    assert.isFalse(guard.viaRemember)
    assert.isUndefined(userProvider.getToken())
  })

  test('do not delete token when value in cookie is invalid', async ({ assert }) => {
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

    await sessionMiddleware.handle(ctx, () => {
      ctx.session.put('auth_web', 1)
      return guard.logout()
    })

    assert.deepEqual(ctx.session.all(), {})
    assert.containsSubset(parseCookies(ctx.response.getHeader('set-cookie') as string), {
      remember_web: {
        maxAge: -1,
        name: 'remember_web',
        value: '',
        expires: new Date(0),
      },
    })
    assert.isUndefined(guard.user)
    assert.isTrue(guard.isLoggedOut)
    assert.isFalse(guard.isAuthenticated)
    assert.isFalse(guard.authenticationAttempted)
    assert.isFalse(guard.viaRemember)
    assert.isDefined(userProvider.getToken())
  })
})

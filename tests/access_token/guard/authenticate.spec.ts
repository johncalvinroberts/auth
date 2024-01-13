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

import { createEmitter, timeTravel } from '../../helpers.js'
import { AccessTokenGuard } from '../../../modules/access_token_guard/guard.js'
import { AccessTokenFakeUserProvider } from '../../../factories/access_token_guard/main.js'

test.group('Access token guard | authenticate', () => {
  test('return user when access token is valid', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokenFakeUserProvider()

    const guard = new AccessTokenGuard('api', ctx, emitter, userProvider)
    const token = await userProvider.createToken(userProvider.findUser(1)!)

    ctx.request.request.headers.authorization = `Bearer ${token.value!.release()}`
    const user = await guard.authenticate()

    assert.deepEqual(guard.user, user)
    assert.deepEqual(guard.getUserOrFail(), user)
    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when no authorization header exists', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokenFakeUserProvider()

    const guard = new AccessTokenGuard('api', ctx, emitter, userProvider)
    await assert.rejects(() => guard.authenticate(), 'Unauthorized access')

    assert.isUndefined(guard.user)
    assert.throws(() => guard.getUserOrFail(), 'Unauthorized access')
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when authorization header does not have a bearer token', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokenFakeUserProvider()
    ctx.request.request.headers.authorization = 'foo bar'

    const guard = new AccessTokenGuard('api', ctx, emitter, userProvider)
    await assert.rejects(() => guard.authenticate(), 'Unauthorized access')

    assert.isUndefined(guard.user)
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when authorization header has an empty bearer token', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokenFakeUserProvider()
    ctx.request.request.headers.authorization = 'Bearer '

    const guard = new AccessTokenGuard('api', ctx, emitter, userProvider)
    await assert.rejects(() => guard.authenticate(), 'Unauthorized access')

    assert.isUndefined(guard.user)
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when bearer token is invalid', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokenFakeUserProvider()
    ctx.request.request.headers.authorization = 'Bearer helloworld'

    const guard = new AccessTokenGuard('api', ctx, emitter, userProvider)
    await assert.rejects(() => guard.authenticate(), 'Unauthorized access')

    assert.isUndefined(guard.user)
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when bearer token does not exist', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokenFakeUserProvider()

    const guard = new AccessTokenGuard('api', ctx, emitter, userProvider)
    const token = await userProvider.createToken(userProvider.findUser(1)!)
    await userProvider.deleteToken(token.value!)

    ctx.request.request.headers.authorization = `Bearer ${token.value!.release()}`
    await assert.rejects(() => guard.authenticate(), 'Unauthorized access')

    assert.isUndefined(guard.user)
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('throw error when bearer token has been expired', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokenFakeUserProvider()

    const guard = new AccessTokenGuard('api', ctx, emitter, userProvider)
    const token = await userProvider.createToken(userProvider.findUser(1)!)
    timeTravel(21 * 60)

    ctx.request.request.headers.authorization = `Bearer ${token.value!.release()}`
    await assert.rejects(() => guard.authenticate(), 'Unauthorized access')

    assert.isUndefined(guard.user)
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('multiple calls to authenticate method should be a noop', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokenFakeUserProvider()

    const guard = new AccessTokenGuard('api', ctx, emitter, userProvider)
    const token = await userProvider.createToken(userProvider.findUser(1)!)
    await assert.rejects(() => guard.authenticate(), 'Unauthorized access')

    ctx.request.request.headers.authorization = `Bearer ${token.value!.release()}`

    /**
     * Even though the token exists now, the authenticate
     * method will use previous state
     */
    await assert.rejects(() => guard.authenticate(), 'Unauthorized access')

    assert.isUndefined(guard.user)
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })
})

test.group('Access token guard | check', () => {
  test('return true when access token is valid', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokenFakeUserProvider()

    const guard = new AccessTokenGuard('api', ctx, emitter, userProvider)
    const token = await userProvider.createToken(userProvider.findUser(1)!)

    ctx.request.request.headers.authorization = `Bearer ${token.value!.release()}`
    const isLoggedIn = await guard.check()

    assert.isTrue(isLoggedIn)
    assert.deepEqual(guard.user, { id: 1, email: 'virk@adonisjs.com', password: 'secret' })
    assert.isTrue(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })

  test('return false when access token is invalid', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokenFakeUserProvider()

    const guard = new AccessTokenGuard('api', ctx, emitter, userProvider)
    const token = await userProvider.createToken(userProvider.findUser(1)!)
    await userProvider.deleteToken(token.value!)

    ctx.request.request.headers.authorization = `Bearer ${token.value!.release()}`
    const isLoggedIn = await guard.check()

    assert.isFalse(isLoggedIn)
    assert.isUndefined(guard.user)
    assert.isFalse(guard.isAuthenticated)
    assert.isTrue(guard.authenticationAttempted)
  })
})

test.group('Access token guard | authenticateAsClient', () => {
  test('return bearer header for client', async ({ assert }) => {
    const ctx = new HttpContextFactory().create()
    const emitter = createEmitter()
    const userProvider = new AccessTokenFakeUserProvider()

    const guard = new AccessTokenGuard('api', ctx, emitter, userProvider)
    const user = userProvider.findUser(1)!

    const clientState = await guard.authenticateAsClient(user)
    assert.property(clientState, 'headers')
    assert.property(clientState.headers, 'Authorization')
    assert.match(clientState.headers!.Authorization, /Bearer oat_[a-zA-z0-9]+\.[a-zA-z0-9]/)
  })
})

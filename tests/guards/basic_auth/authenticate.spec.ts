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
import { FactoryUser } from '../../../factories/lucid_user_provider.js'
import { pEvent, createTables, createDatabase, createEmitter } from '../../helpers.js'
import { BasicAuthGuardFactory } from '../../../factories/basic_auth_guard_factory.js'

test.group('BasicAuth guard | authenticate', () => {
  test('authenticate user using credentials', async ({ assert, expectTypeOf }) => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const user = await FactoryUser.createWithDefaults({
      password: await new Scrypt({}).make('secret'),
    })

    const basicAuthGuard = new BasicAuthGuardFactory().create(ctx).setEmitter(emitter)

    ctx.request.request.headers.authorization = `Basic ${Buffer.from(
      `${user.email}:secret`
    ).toString('base64')}`

    const [authSucceeded] = await Promise.all([
      pEvent(emitter, 'basic_auth:authentication_succeeded'),
      basicAuthGuard.authenticate(),
    ])

    expectTypeOf(basicAuthGuard.authenticate).returns.toMatchTypeOf<Promise<FactoryUser>>()
    assert.equal(authSucceeded!.user.id, user.id)
    assert.equal(authSucceeded!.user.id, basicAuthGuard.getUserOrFail().id)
    assert.equal(basicAuthGuard.getUserOrFail().id, user.id)
    assert.isTrue(basicAuthGuard.isAuthenticated)
    assert.isTrue(basicAuthGuard.authenticationAttempted)
  })

  test('check if user is logged in using check method', async ({ assert, expectTypeOf }) => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const user = await FactoryUser.createWithDefaults({
      password: await new Scrypt({}).make('secret'),
    })

    const basicAuthGuard = new BasicAuthGuardFactory().create(ctx).setEmitter(emitter)

    ctx.request.request.headers.authorization = `Basic ${Buffer.from(
      `${user.email}:secret`
    ).toString('base64')}`

    const [authSucceeded, state] = await Promise.all([
      pEvent(emitter, 'basic_auth:authentication_succeeded'),
      basicAuthGuard.check(),
    ])

    assert.isTrue(state)
    expectTypeOf(basicAuthGuard.authenticate).returns.toMatchTypeOf<Promise<FactoryUser>>()
    assert.equal(authSucceeded!.user.id, user.id)
    assert.equal(authSucceeded!.user.id, basicAuthGuard.getUserOrFail().id)
    assert.equal(basicAuthGuard.getUserOrFail().id, user.id)
    assert.isTrue(basicAuthGuard.isAuthenticated)
    assert.isTrue(basicAuthGuard.authenticationAttempted)
  })

  test('throw error when credentials are missing', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const basicAuthGuard = new BasicAuthGuardFactory().create(ctx).setEmitter(emitter)

    const [authFailed, authentication] = await Promise.allSettled([
      pEvent(emitter, 'basic_auth:authentication_failed'),
      basicAuthGuard.authenticate(),
    ])

    assert.equal(authFailed.status, 'fulfilled')
    assert.equal(authentication.status, 'rejected')

    if (authFailed.status === 'fulfilled') {
      assert.equal(authFailed.value!.error.message, 'Invalid basic auth credentials')
    }
    if (authentication.status === 'rejected') {
      assert.equal(authentication.reason.message, 'Invalid basic auth credentials')
    }

    assert.isTrue(basicAuthGuard.authenticationAttempted)
    assert.isFalse(basicAuthGuard.isAuthenticated)
    assert.isUndefined(basicAuthGuard.user)
  })

  test('throw error when user does not exists', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const basicAuthGuard = new BasicAuthGuardFactory().create(ctx).setEmitter(emitter)

    ctx.request.request.headers.authorization = `Basic ${Buffer.from(`foo:secret`).toString(
      'base64'
    )}`

    const [authFailed, authentication] = await Promise.allSettled([
      pEvent(emitter, 'basic_auth:authentication_failed'),
      basicAuthGuard.authenticate(),
    ])

    assert.equal(authFailed.status, 'fulfilled')
    assert.equal(authentication.status, 'rejected')

    if (authFailed.status === 'fulfilled') {
      assert.equal(authFailed.value!.error.message, 'Invalid basic auth credentials')
    }
    if (authentication.status === 'rejected') {
      assert.equal(authentication.reason.message, 'Invalid basic auth credentials')
    }

    assert.isTrue(basicAuthGuard.authenticationAttempted)
    assert.isFalse(basicAuthGuard.isAuthenticated)
    assert.isUndefined(basicAuthGuard.user)
  })

  test('throw error when password is invalid', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const user = await FactoryUser.createWithDefaults({
      password: await new Scrypt({}).make('secret'),
    })
    const basicAuthGuard = new BasicAuthGuardFactory().create(ctx).setEmitter(emitter)

    ctx.request.request.headers.authorization = `Basic ${Buffer.from(
      `${user.email}:wrongpassword`
    ).toString('base64')}`

    const [authFailed, authentication] = await Promise.allSettled([
      pEvent(emitter, 'basic_auth:authentication_failed'),
      basicAuthGuard.authenticate(),
    ])

    assert.equal(authFailed.status, 'fulfilled')
    assert.equal(authentication.status, 'rejected')

    if (authFailed.status === 'fulfilled') {
      assert.equal(authFailed.value!.error.message, 'Invalid basic auth credentials')
    }
    if (authentication.status === 'rejected') {
      assert.equal(authentication.reason.message, 'Invalid basic auth credentials')
    }

    assert.isTrue(basicAuthGuard.authenticationAttempted)
    assert.isFalse(basicAuthGuard.isAuthenticated)
    assert.isUndefined(basicAuthGuard.user)
  })

  test('throw error when called getUserOrFail', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const basicAuthGuard = new BasicAuthGuardFactory().create(ctx).setEmitter(emitter)

    const [authFailed, authentication] = await Promise.allSettled([
      pEvent(emitter, 'basic_auth:authentication_failed'),
      basicAuthGuard.authenticate(),
    ])

    assert.equal(authFailed.status, 'fulfilled')
    assert.equal(authentication.status, 'rejected')

    if (authFailed.status === 'fulfilled') {
      assert.equal(authFailed.value!.error.message, 'Invalid basic auth credentials')
    }
    if (authentication.status === 'rejected') {
      assert.equal(authentication.reason.message, 'Invalid basic auth credentials')
    }

    assert.isTrue(basicAuthGuard.authenticationAttempted)
    assert.isFalse(basicAuthGuard.isAuthenticated)
    assert.throws(() => basicAuthGuard.getUserOrFail(), 'Invalid basic auth credentials')
  })

  test('throw error when calling check after authenticate and user is not authenticated', async ({
    assert,
  }) => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const user = await FactoryUser.createWithDefaults({
      password: await new Scrypt({}).make('secret'),
    })
    const basicAuthGuard = new BasicAuthGuardFactory().create(ctx).setEmitter(emitter)

    ctx.request.request.headers.authorization = `Basic ${Buffer.from(
      `${user.email}:wrongpassword`
    ).toString('base64')}`

    const [authFailed, , authentication] = await Promise.allSettled([
      pEvent(emitter, 'basic_auth:authentication_failed'),
      basicAuthGuard.check(),
      basicAuthGuard.authenticate(),
    ])

    assert.equal(authFailed.status, 'fulfilled')
    assert.equal(authentication.status, 'rejected')

    if (authFailed.status === 'fulfilled') {
      assert.equal(authFailed.value!.error.message, 'Invalid basic auth credentials')
    }
    if (authentication.status === 'rejected') {
      assert.equal(authentication.reason.message, 'Invalid basic auth credentials')
    }

    assert.isTrue(basicAuthGuard.authenticationAttempted)
    assert.isFalse(basicAuthGuard.isAuthenticated)
    assert.isUndefined(basicAuthGuard.user)
  })

  test('throw error when calling authenticateAsClient', async () => {
    const db = await createDatabase()
    await createTables(db)

    const emitter = createEmitter()
    const user = await FactoryUser.createWithDefaults({
      password: await new Scrypt({}).make('secret'),
    })
    const ctx = new HttpContextFactory().create()
    const basicAuthGuard = new BasicAuthGuardFactory().create(ctx).setEmitter(emitter)
    await basicAuthGuard.authenticateAsClient(user)
  }).throws('Cannot authenticate as a client when using basic auth')
})

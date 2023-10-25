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
import { AuthenticationException, InvalidCredentialsException } from '../../src/auth/errors.js'

test.group('Errors | AuthenticationException', () => {
  test('handle session guard exception with a redirect', async ({ assert }) => {
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const error = new AuthenticationException('Unauthorized access', {
      guardDriverName: 'session',
    })

    const ctx = new HttpContextFactory().create()
    await sessionMiddleware.handle(ctx, async () => {
      return error.handle(error, ctx)
    })

    assert.deepEqual(ctx.session.responseFlashMessages.all(), {
      errors: { 'auth.authenticate': ['Unauthorized access'] },
      input: {},
    })
    assert.equal(ctx.response.getHeader('location'), '/')
  })

  test('handle session guard exception with a redirect to a custom location', async ({
    assert,
  }) => {
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const error = new AuthenticationException('Unauthorized access', {
      guardDriverName: 'session',
      redirectTo: '/login',
    })

    const ctx = new HttpContextFactory().create()
    await sessionMiddleware.handle(ctx, async () => {
      return error.handle(error, ctx)
    })

    assert.deepEqual(ctx.session.responseFlashMessages.all(), {
      errors: { 'auth.authenticate': ['Unauthorized access'] },
      input: {},
    })
    assert.equal(ctx.response.getHeader('location'), '/login')
  })

  test('handle session guard exception with JSON response', async ({ assert }) => {
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const error = new AuthenticationException('Unauthorized access', {
      guardDriverName: 'session',
      redirectTo: '/login',
    })

    const ctx = new HttpContextFactory().create()

    /**
     * The accept header will force a JSON response
     */
    ctx.request.request.headers.accept = 'application/json'

    await sessionMiddleware.handle(ctx, async () => {
      return error.handle(error, ctx)
    })

    assert.deepEqual(ctx.response.getBody(), {
      errors: [
        {
          message: 'Unauthorized access',
        },
      ],
    })
    assert.isUndefined(ctx.response.getHeader('location'))
    assert.deepEqual(ctx.session.responseFlashMessages.all(), {})
  })

  test('handle session guard exception with JSONAPI response', async ({ assert }) => {
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const error = new AuthenticationException('Unauthorized access', {
      guardDriverName: 'session',
      redirectTo: '/login',
    })

    const ctx = new HttpContextFactory().create()

    /**
     * The accept header will force a JSONAPI response
     */
    ctx.request.request.headers.accept = 'application/vnd.api+json'

    await sessionMiddleware.handle(ctx, async () => {
      return error.handle(error, ctx)
    })

    assert.deepEqual(ctx.response.getBody(), {
      errors: [
        {
          title: 'Unauthorized access',
          code: 'auth.authenticate',
        },
      ],
    })
    assert.isUndefined(ctx.response.getHeader('location'))
    assert.deepEqual(ctx.session.responseFlashMessages.all(), {})
  })

  test('send plain text response when there is no renderer for a guard', async ({ assert }) => {
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const error = new AuthenticationException('Unauthorized access', {
      guardDriverName: 'foo',
      redirectTo: '/login',
      status: 401,
    })

    const ctx = new HttpContextFactory().create()
    await sessionMiddleware.handle(ctx, async () => {
      return error.handle(error, ctx)
    })

    assert.equal(ctx.response.getStatus(), 401)
    assert.equal(ctx.response.getBody(), 'Unauthorized access')
  })
})

test.group('Errors | InvalidCredentialsException', () => {
  test('handle session guard exception with a redirect', async ({ assert }) => {
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const error = InvalidCredentialsException.E_INVALID_CREDENTIALS('session')

    const ctx = new HttpContextFactory().create()
    await sessionMiddleware.handle(ctx, async () => {
      return error.handle(error, ctx)
    })

    assert.deepEqual(ctx.session.responseFlashMessages.all(), {
      errors: { 'auth.login': ['Invalid credentials'] },
      input: {},
    })
    assert.equal(ctx.response.getHeader('location'), '/')
  })

  test('handle session guard exception with a JSON response', async ({ assert }) => {
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const error = InvalidCredentialsException.E_INVALID_CREDENTIALS('session')

    const ctx = new HttpContextFactory().create()

    /**
     * The accept header will force a JSON response
     */
    ctx.request.request.headers.accept = 'application/json'

    await sessionMiddleware.handle(ctx, async () => {
      return error.handle(error, ctx)
    })

    assert.deepEqual(ctx.response.getBody(), {
      errors: [
        {
          message: 'Invalid credentials',
        },
      ],
    })
    assert.isUndefined(ctx.response.getHeader('location'))
    assert.deepEqual(ctx.session.responseFlashMessages.all(), {})
  })

  test('handle session guard exception with a JSONAPI response', async ({ assert }) => {
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const error = InvalidCredentialsException.E_INVALID_CREDENTIALS('session')

    const ctx = new HttpContextFactory().create()

    /**
     * The accept header will force a JSON response
     */
    ctx.request.request.headers.accept = 'application/vnd.api+json'

    await sessionMiddleware.handle(ctx, async () => {
      return error.handle(error, ctx)
    })

    assert.deepEqual(ctx.response.getBody(), {
      errors: [
        {
          title: 'Invalid credentials',
          code: 'auth.login',
        },
      ],
    })
    assert.isUndefined(ctx.response.getHeader('location'))
    assert.deepEqual(ctx.session.responseFlashMessages.all(), {})
  })

  test('respond with plain text when there is no renderer for guard', async ({ assert }) => {
    const sessionMiddleware = await new SessionMiddlewareFactory().create()
    const error = InvalidCredentialsException.E_INVALID_CREDENTIALS('foo')

    const ctx = new HttpContextFactory().create()
    await sessionMiddleware.handle(ctx, async () => {
      return error.handle(error, ctx)
    })

    assert.equal(ctx.response.getBody(), 'Invalid credentials')
    assert.isUndefined(ctx.response.getHeader('location'))
    assert.deepEqual(ctx.session.responseFlashMessages.all(), {})
  })
})

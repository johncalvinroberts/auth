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

import { createEmitter } from '../helpers.js'
import { Authenticator } from '../../src/auth/authenticator.js'
import { FactoryUser } from '../../factories/lucid_user_provider.js'
import { SessionGuardFactory } from '../../factories/session_guard_factory.js'

test.group('Authenticator', () => {
  test('create authenticator with guards', async ({ assert, expectTypeOf }) => {
    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const sessionGuard = new SessionGuardFactory().create(ctx).withEmitter(emitter)

    const authenticator = new Authenticator(ctx, {
      default: 'web',
      guards: {
        web: () => sessionGuard,
      },
    })

    assert.instanceOf(authenticator, Authenticator)
    expectTypeOf(authenticator.use).parameters.toMatchTypeOf<['web'?]>()
  })

  test('access guard using its name', async ({ assert, expectTypeOf }) => {
    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const sessionGuard = new SessionGuardFactory().create(ctx).withEmitter(emitter)

    const authenticator = new Authenticator(ctx, {
      default: 'web',
      guards: {
        web: () => sessionGuard,
      },
    })

    const webGuard = authenticator.use('web')
    assert.strictEqual(webGuard, sessionGuard)
    assert.strictEqual(authenticator.use('web'), authenticator.use('web'))
    expectTypeOf(webGuard.user).toMatchTypeOf<FactoryUser | undefined>()
  })
})

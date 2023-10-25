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
import { AuthManager } from '../../src/auth/auth_manager.js'
import { Authenticator } from '../../src/auth/authenticator.js'
import { SessionGuardFactory } from '../../factories/session_guard_factory.js'

test.group('Auth manager', () => {
  test('create authenticator from auth manager', async ({ assert, expectTypeOf }) => {
    const emitter = createEmitter()
    const ctx = new HttpContextFactory().create()
    const sessionGuard = new SessionGuardFactory().create(ctx).withEmitter(emitter)

    const authManager = new AuthManager({
      default: 'web',
      loginRoute: '/login',
      guards: {
        web: () => sessionGuard,
      },
    })

    assert.equal(authManager.defaultGuard, 'web')
    assert.instanceOf(authManager.createAuthenticator(ctx), Authenticator)
    expectTypeOf(authManager.createAuthenticator(ctx).use).parameters.toMatchTypeOf<['web'?]>()
  })
})

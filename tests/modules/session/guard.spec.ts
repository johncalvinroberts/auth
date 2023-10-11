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

import { createDatabase, createTables } from '../../helpers.js'
import { FactoryUser } from '../../../factories/lucid_user_provider.js'
import { SessionGuardFactory } from '../../../factories/session_guard_factory.js'

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

    assert.deepEqual(ctx.session.all(), { auth_web: user.id })
  })
})

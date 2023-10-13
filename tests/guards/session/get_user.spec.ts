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

import { createTables, createDatabase } from '../../helpers.js'
import { FactoryUser } from '../../../factories/lucid_user_provider.js'
import { SessionGuardFactory } from '../../../factories/session_guard_factory.js'

test.group('Session guard | getUser', () => {
  test('get user when authentication succeeded', async ({ assert, expectTypeOf }) => {
    const db = await createDatabase()
    await createTables(db)

    const ctx = new HttpContextFactory().create()
    const user = await FactoryUser.createWithDefaults()
    const sessionGuard = new SessionGuardFactory().create(ctx)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    await sessionMiddleware.handle(ctx, async () => {
      ctx.session.put('auth_web', user.id)
      await sessionGuard.authenticate()
    })

    assert.equal(sessionGuard.getUserOrFail().id, user.id)
    expectTypeOf(sessionGuard.getUserOrFail()).toMatchTypeOf<FactoryUser>()
  })

  test('throw error when authentication failed and getUser is called', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const ctx = new HttpContextFactory().create()
    const sessionGuard = new SessionGuardFactory().create(ctx)
    const sessionMiddleware = await new SessionMiddlewareFactory().create()

    await assert.rejects(async () => {
      await sessionMiddleware.handle(ctx, async () => {
        await sessionGuard.authenticate()
      })
    })

    assert.throws(() => sessionGuard.getUserOrFail(), 'Invalid or expired authentication session')
  })
})

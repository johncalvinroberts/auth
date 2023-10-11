/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { createDatabase, createTables } from '../../../helpers.js'
import { FactoryUser } from '../../../../factories/lucid_user_provider.js'
import { DatabaseUserProviderFactory } from '../../../../factories/database_user_provider.js'

test.group('Database user provider | findByUId', () => {
  test('find a user using primary key', async ({ assert, expectTypeOf }) => {
    const db = await createDatabase()
    await createTables(db)

    await FactoryUser.createWithDefaults()

    const dbUserProvider = new DatabaseUserProviderFactory().create(db)
    const userByUsername = await dbUserProvider.findByUid('foo')
    const userByEmail = await dbUserProvider.findByUid('foo@bar.com')

    expectTypeOf(userByUsername!.getOriginal()).toMatchTypeOf<any>()
    assert.equal(userByUsername!.getId(), 1)
    assert.deepEqual(userByUsername!.getOriginal(), {
      id: 1,
      email: 'foo@bar.com',
      username: 'foo',
      password: 'secret',
    })

    expectTypeOf(userByEmail!.getOriginal()).toMatchTypeOf<any>()
    assert.equal(userByEmail!.getId(), 1)
    assert.deepEqual(userByEmail!.getOriginal(), {
      id: 1,
      email: 'foo@bar.com',
      username: 'foo',
      password: 'secret',
    })
  })

  test('return null when unable to find user by uid', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const dbUserProvider = new DatabaseUserProviderFactory().create(db)

    assert.isNull(await dbUserProvider.findByUid('foo@bar.com'))
    assert.isNull(await dbUserProvider.findByUid('foo'))
  })
})

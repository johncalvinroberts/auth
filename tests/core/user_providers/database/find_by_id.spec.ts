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
import { FactoryUser } from '../../../../factories/core/lucid_user_provider.js'
import { DatabaseUserProviderFactory } from '../../../../factories/core/database_user_provider.js'

test.group('Database user provider | findById', () => {
  test('find a user using primary key', async ({ assert, expectTypeOf }) => {
    const db = await createDatabase()
    await createTables(db)

    await FactoryUser.createWithDefaults()

    const dbUserProvider = new DatabaseUserProviderFactory().create(db)
    const userById = await dbUserProvider.findById(1)

    expectTypeOf(userById!.getOriginal()).toMatchTypeOf<any>()
    assert.deepEqual(userById!.getOriginal(), {
      id: 1,
      email: 'foo@bar.com',
      username: 'foo',
      password: 'secret',
    })
    assert.equal(userById!.getId(), 1)
  })

  test('return null when unable to find user by id', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const dbUserProvider = new DatabaseUserProviderFactory().create(db)
    const userById = await dbUserProvider.findById(1)

    assert.isNull(userById)
  })
})

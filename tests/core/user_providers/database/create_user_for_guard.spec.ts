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

test.group('Database user provider | createUserForGuard', () => {
  test('create a guard user from database row', async ({ assert, expectTypeOf }) => {
    const db = await createDatabase()
    await createTables(db)

    const { id } = await FactoryUser.createWithDefaults()
    const user = await db.connection().from('users').where('id', id).first()

    const dbUserProvider = new DatabaseUserProviderFactory().create(db)
    const providerUser = await dbUserProvider.createUserForGuard(user)

    expectTypeOf(providerUser.getOriginal()).toMatchTypeOf<any>()
    assert.equal(providerUser.getId(), 1)
    assert.deepEqual(providerUser.getOriginal(), {
      id: 1,
      email: 'foo@bar.com',
      username: 'foo',
      password: 'secret',
    })
  })

  test('return error when user value is not an object', async () => {
    const db = await createDatabase()
    await createTables(db)

    const dbUserProvider = new DatabaseUserProviderFactory().create(db)
    await dbUserProvider.createUserForGuard(null as any)
  }).throws('Invalid user object. It must be a database row object from the "users" table')

  test('return error when value primaryColumn is missing', async () => {
    const db = await createDatabase()
    await createTables(db)

    const { id } = await FactoryUser.createWithDefaults()
    const user = await db.connection().from('users').where('id', id).first()
    delete user.id

    const dbUserProvider = new DatabaseUserProviderFactory().create(db)
    const providerUser = await dbUserProvider.createUserForGuard(user)
    providerUser.getId()
  }).throws('Invalid user object. The value of column "id" is undefined or null')
})

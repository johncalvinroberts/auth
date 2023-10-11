/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { createDatabase, createTables, getHasher } from '../../../helpers.js'
import { FactoryUser } from '../../../../factories/lucid_user_provider.js'
import { DatabaseUserProviderFactory } from '../../../../factories/database_user_provider.js'

test.group('Database user provider | createUserForGuard', () => {
  test('verify user password using guard user instance', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    await FactoryUser.createWithDefaults({
      password: await getHasher().make('secret'),
    })

    const dbUserProvider = new DatabaseUserProviderFactory().create(db)
    const user = await dbUserProvider.findByUid('foo@bar.com')

    assert.isTrue(await user!.verifyPassword('secret'))
    assert.isFalse(await user!.verifyPassword('foobar'))
  })

  test('throw error when value of password column is missing', async () => {
    const db = await createDatabase()
    await createTables(db)

    await FactoryUser.createWithDefaults({
      password: null,
    })

    const dbUserProvider = new DatabaseUserProviderFactory().create(db)
    const user = await dbUserProvider.findByUid('foo@bar.com')

    await user!.verifyPassword('secret')
  }).throws(
    'Cannot verify password during login. The value of column "password" is undefined or null'
  )

  test('throw error when value of id column is missing', async () => {
    const db = await createDatabase()
    await createTables(db)

    const dbUserProvider = new DatabaseUserProviderFactory().create(db)
    const user = await dbUserProvider.createUserForGuard({ email: 'foo@bar.com', username: 'foo' })

    user!.getId()
  }).throws('Invalid user object. The value of column "id" is undefined or null')
})

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
import { FactoryUser, LucidUserProviderFactory } from '../../../../factories/lucid_user_provider.js'

test.group('Lucid user provider | LucidUser', () => {
  test('verify user password using guard user instance', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    await FactoryUser.createWithDefaults({
      password: await getHasher().make('secret'),
    })

    const lucidUserProvider = new LucidUserProviderFactory().create()

    const user = await lucidUserProvider.findByUid('foo@bar.com')
    assert.isTrue(await user!.verifyPassword('secret'))
    assert.isFalse(await user!.verifyPassword('foobar'))
  })

  test('throw error when value of password column is missing', async () => {
    const db = await createDatabase()
    await createTables(db)

    await FactoryUser.createWithDefaults({
      password: null,
    })

    const lucidUserProvider = new LucidUserProviderFactory().create()
    const user = await lucidUserProvider.findByUid('foo@bar.com')

    await user!.verifyPassword('secret')
  }).throws(
    'Cannot verify password during login. The value of column "password" is undefined or null'
  )

  test('throw error when user primary key is missing', async () => {
    const db = await createDatabase()
    await createTables(db)

    const lucidUserProvider = new LucidUserProviderFactory().create()

    const user = await lucidUserProvider.createUserForGuard(new FactoryUser())
    user.getId()
  }).throws(
    'Cannot use "FactoryUser" model for authentication. The value of column "id" is undefined or null'
  )
})

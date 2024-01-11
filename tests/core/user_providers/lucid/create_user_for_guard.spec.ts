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
import {
  FactoryUser,
  LucidUserProviderFactory,
} from '../../../../factories/core/lucid_user_provider.js'

test.group('Lucid user provider | createUserForGuard', () => {
  test('create a guard user from a model instance', async ({ assert, expectTypeOf }) => {
    const db = await createDatabase()
    await createTables(db)

    const user = await FactoryUser.create({
      email: 'foo@bar.com',
      username: 'foo',
      password: 'secret',
    })

    const lucidUserProvider = new LucidUserProviderFactory().create()
    const providerUser = await lucidUserProvider.createUserForGuard(user)

    expectTypeOf(providerUser.getOriginal()).toMatchTypeOf<InstanceType<typeof FactoryUser>>()
    assert.instanceOf(providerUser.getOriginal(), FactoryUser)
    assert.isFalse(providerUser.getOriginal().$isNew)
    assert.equal(providerUser.getId(), 1)
  })

  test('return error when user is not an instance of Model', async () => {
    const db = await createDatabase()
    await createTables(db)

    const lucidUserProvider = new LucidUserProviderFactory().create()
    await lucidUserProvider.createUserForGuard({} as any)
  }).throws('Invalid user object. It must be an instance of the "FactoryUser" model')

  test('return error when user primary key is missing', async () => {
    const db = await createDatabase()
    await createTables(db)

    const lucidUserProvider = new LucidUserProviderFactory().create()
    const user = await lucidUserProvider.createUserForGuard(new FactoryUser())
    user.getId()
  }).throws(
    'Cannot use "FactoryUser" model for authentication. The value of column "id" is undefined or null'
  )
})

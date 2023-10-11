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
import { FactoryUser, LucidUserProviderFactory } from '../../../../factories/lucid_user_provider.js'

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
    const userByInstance = await lucidUserProvider.createUserForGuard(user)

    expectTypeOf(userByInstance!.getOriginal()).toMatchTypeOf<InstanceType<typeof FactoryUser>>()
    assert.instanceOf(userByInstance!.getOriginal(), FactoryUser)
    assert.isFalse(userByInstance!.getOriginal().$isNew)
    assert.equal(userByInstance!.getId(), 1)
  })

  test('return error when user is not an instance of Model', async () => {
    const db = await createDatabase()
    await createTables(db)

    const lucidUserProvider = new LucidUserProviderFactory().create()
    await lucidUserProvider.createUserForGuard({} as any)
  }).throws('Invalid user object. It must be an instance of the "FactoryUser" model')
})

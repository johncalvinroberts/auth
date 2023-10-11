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

test.group('Lucid user provider | findById', () => {
  test('find a user using primary key', async ({ assert, expectTypeOf }) => {
    const db = await createDatabase()
    await createTables(db)

    await FactoryUser.create({ email: 'foo@bar.com', username: 'foo', password: 'secret' })

    const lucidUserProvider = new LucidUserProviderFactory().create()
    const userById = await lucidUserProvider.findById(1)

    expectTypeOf(userById!.getOriginal()).toMatchTypeOf<InstanceType<typeof FactoryUser>>()
    assert.instanceOf(userById!.getOriginal(), FactoryUser)
    assert.isFalse(userById!.getOriginal().$isNew)
    assert.equal(userById!.getId(), 1)
  })

  test('return null when unable to find user by id', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const lucidUserProvider = new LucidUserProviderFactory().create()
    const userById = await lucidUserProvider.findById(1)

    assert.isNull(userById)
  })
})

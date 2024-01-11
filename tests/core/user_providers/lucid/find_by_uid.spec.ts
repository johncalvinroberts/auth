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

test.group('Lucid user provider | findByUid', () => {
  test('find a user for login using uids', async ({ assert, expectTypeOf }) => {
    const db = await createDatabase()
    await createTables(db)

    await FactoryUser.create({ email: 'foo@bar.com', username: 'foo', password: 'secret' })

    const lucidUserProvider = new LucidUserProviderFactory().create()
    const userByEmail = await lucidUserProvider.findByUid('foo@bar.com')
    const userByUsername = await lucidUserProvider.findByUid('foo@bar.com')

    expectTypeOf(userByEmail!.getOriginal()).toMatchTypeOf<InstanceType<typeof FactoryUser>>()
    assert.instanceOf(userByEmail!.getOriginal(), FactoryUser)
    assert.isFalse(userByEmail!.getOriginal().$isNew)
    assert.equal(userByEmail!.getId(), 1)

    expectTypeOf(userByUsername!.getOriginal()).toMatchTypeOf<InstanceType<typeof FactoryUser>>()
    assert.instanceOf(userByUsername!.getOriginal(), FactoryUser)
    assert.isFalse(userByUsername!.getOriginal().$isNew)
    assert.equal(userByUsername!.getId(), 1)
  })

  test('customize user lookup by defining "getUserForAuth" method', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    class CustomUser extends FactoryUser {
      static async getUserForAuth(uids: string[], value: number | string) {
        assert.deepEqual(uids, ['email'])
        assert.equal(value, 'foo@bar.com')
        return null
      }
    }

    const lucidUserProvider = new LucidUserProviderFactory().createForModel({
      model: async () => {
        return {
          default: CustomUser,
        }
      },
      passwordColumnName: 'password',
      uids: ['email'],
    })

    const userByEmail = await lucidUserProvider.findByUid('foo@bar.com')
    assert.isNull(userByEmail)
  })

  test('create provider user from value returned by "getUserForAuth"', async ({
    assert,
    expectTypeOf,
  }) => {
    const db = await createDatabase()
    await createTables(db)

    class CustomUser extends FactoryUser {
      static async getUserForAuth(uids: string[], value: number | string) {
        const user = await this.query().where(uids[0], value).first()
        return user
      }
    }

    const lucidUserProvider = new LucidUserProviderFactory().createForModel({
      model: async () => {
        return {
          default: CustomUser,
        }
      },
      passwordColumnName: 'password',
      uids: ['email'],
    })
    await CustomUser.create({ email: 'foo@bar.com', username: 'foo', password: 'secret' })

    const userByEmail = await lucidUserProvider.findByUid('foo@bar.com')
    const userByUsername = await lucidUserProvider.findByUid('foo@bar.com')

    expectTypeOf(userByEmail!.getOriginal()).toMatchTypeOf<InstanceType<typeof FactoryUser>>()
    assert.instanceOf(userByEmail!.getOriginal(), FactoryUser)
    assert.isFalse(userByEmail!.getOriginal().$isNew)
    assert.equal(userByEmail!.getId(), 1)

    expectTypeOf(userByUsername!.getOriginal()).toMatchTypeOf<InstanceType<typeof FactoryUser>>()
    assert.instanceOf(userByUsername!.getOriginal(), FactoryUser)
    assert.isFalse(userByUsername!.getOriginal().$isNew)
    assert.equal(userByUsername!.getId(), 1)
  })

  test('return null when unable to find user by uid', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const lucidUserProvider = new LucidUserProviderFactory().create()

    assert.isNull(await lucidUserProvider.findByUid('foo@bar.com'))
    assert.isNull(await lucidUserProvider.findByUid('foo'))
  })
})

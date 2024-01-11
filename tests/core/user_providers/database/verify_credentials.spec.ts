/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import convertHrtime from 'convert-hrtime'
import { FactoryUser } from '../../../../factories/lucid_user_provider.js'
import { createDatabase, createTables, getHasher } from '../../../helpers.js'
import { DatabaseUserProviderFactory } from '../../../../factories/database_user_provider.js'

test.group('Database user provider | verifyCredentials', () => {
  test('return user when email and password are correct', async ({ assert, expectTypeOf }) => {
    const db = await createDatabase()
    await createTables(db)

    await FactoryUser.createWithDefaults({
      email: 'foo@bar.com',
      username: 'foo',
      password: await getHasher().make('secret'),
    })

    const dbUserProvider = new DatabaseUserProviderFactory().create(db)
    const userByEmail = await dbUserProvider.verifyCredentials('foo@bar.com', 'secret')

    expectTypeOf(userByEmail!.getOriginal()).toMatchTypeOf<any>()
    assert.equal(userByEmail!.getId(), 1)
    assert.containsSubset(userByEmail!.getOriginal(), {
      id: 1,
      email: 'foo@bar.com',
      username: 'foo',
    })
  })

  test('return null when password is invalid', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    await FactoryUser.createWithDefaults({
      email: 'foo@bar.com',
      username: 'foo',
      password: await getHasher().make('secret'),
    })

    const dbUserProvider = new DatabaseUserProviderFactory().create(db)
    const userByEmail = await dbUserProvider.verifyCredentials('foo@bar.com', 'supersecret')
    assert.isNull(userByEmail)
  })

  test('return null when email is incorrect', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    await FactoryUser.createWithDefaults({
      email: 'foo@bar.com',
      username: 'foo',
      password: await getHasher().make('secret'),
    })

    const dbUserProvider = new DatabaseUserProviderFactory().create(db)
    const userByEmail = await dbUserProvider.verifyCredentials('bar@bar.com', 'secret')
    assert.isNull(userByEmail)
  })

  test('prevent timing attacks when email or password are invalid', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    await FactoryUser.createWithDefaults({
      email: 'foo@bar.com',
      username: 'foo',
      password: await getHasher().make('secret'),
    })

    const dbUserProvider = new DatabaseUserProviderFactory().create(db)
    let startTime = process.hrtime.bigint()
    await dbUserProvider.verifyCredentials('baz@bar.com', 'secret')
    const invalidEmailTime = convertHrtime(process.hrtime.bigint() - startTime)

    startTime = process.hrtime.bigint()
    await dbUserProvider.verifyCredentials('foo@bar.com', 'supersecret')
    const invalidPasswordTime = convertHrtime(process.hrtime.bigint() - startTime)

    /**
     * Same timing within the range of 10 milliseconds is acceptable
     */
    assert.isBelow(Math.abs(invalidPasswordTime.seconds - invalidEmailTime.seconds), 1)
    assert.isBelow(Math.abs(invalidPasswordTime.milliseconds - invalidEmailTime.milliseconds), 10)
  })
})

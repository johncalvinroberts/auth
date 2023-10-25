/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { createDatabase, createTables, timeTravel } from '../../helpers.js'
import { DatabaseTokenProviderFactory, TestToken } from '../../../factories/main.js'

test.group('Database token provider | createToken', () => {
  test('persist a token to the database', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const token = TestToken.create(1, '10mins')
    const databaseProvider = new DatabaseTokenProviderFactory().create(db)

    await databaseProvider.createToken(token)
    const tokens = await db.query().from('remember_me_tokens')

    assert.lengthOf(tokens, 1)
    assert.equal(tokens[0].user_id, 1)
    assert.equal(tokens[0].series, token.series)
    assert.exists(tokens[0].created_at)
    assert.exists(tokens[0].updated_at)
    assert.isAbove(tokens[0].expires_at, tokens[0].created_at)

    /**
     * Creating a fresh token from the database entry
     */
    const freshToken = new TestToken(tokens[0].series, undefined, tokens[0].token)

    /**
     * Verifying the token public value matches the saved hash
     */
    const { value } = TestToken.decode(token.value!)!
    assert.isTrue(freshToken.verify(value))
  })

  test('find token by series', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const token = TestToken.create(1, '10mins')
    const databaseProvider = new DatabaseTokenProviderFactory().create(db)

    await databaseProvider.createToken(token)
    const freshToken = await databaseProvider.getTokenBySeries(token.series)

    /**
     * Verifying the token public value matches the saved hash
     */
    const { value } = TestToken.decode(token.value!)!
    assert.isTrue(freshToken!.verify(value))
  })

  test("return null when token doesn't exists", async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const databaseProvider = new DatabaseTokenProviderFactory().create(db)

    assert.isNull(await databaseProvider.getTokenBySeries('foobar'))
  })

  test('return null when token is expired', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const token = TestToken.create(1, '2 sec')
    const databaseProvider = new DatabaseTokenProviderFactory().create(db)

    await databaseProvider.createToken(token)
    timeTravel(3)

    assert.isNull(await databaseProvider.getTokenBySeries(token.series))
  })

  test('update token hash and expiry', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const token = TestToken.create(1, '2sec')
    const databaseProvider = new DatabaseTokenProviderFactory().create(db)

    await databaseProvider.createToken(token)

    /**
     * Wait for the token expire
     */
    timeTravel(3)
    assert.isNull(await databaseProvider.getTokenBySeries(token.series))

    /**
     * Update token expiry
     */
    const dateInFuture = new Date()
    dateInFuture.setSeconds(dateInFuture.getSeconds() * 60)
    await databaseProvider.updateTokenBySeries(token.series, token.hash, dateInFuture)

    /**
     * Ensure it has been set properly
     */
    const freshToken = await databaseProvider.getTokenBySeries(token.series)
    assert.isTrue(freshToken!.expiresAt! > new Date())
  }).timeout(4000)

  test('delete token by series', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const token = TestToken.create(1, '10mins')
    const databaseProvider = new DatabaseTokenProviderFactory().create(db)

    await databaseProvider.createToken(token)
    assert.isNotNull(await databaseProvider.getTokenBySeries(token.series))

    await databaseProvider.deleteTokenBySeries(token.series)
    assert.isNull(await databaseProvider.getTokenBySeries(token.series))
  })
})

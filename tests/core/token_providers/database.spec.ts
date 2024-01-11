/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { createDatabase, createTables } from '../../helpers.js'
import { DatabaseTokenProviderFactory } from '../../../factories/core/database_token_factory.js'

test.group('Database token provider | createToken', () => {
  test('persist a token to the database', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const token = { series: '12345', hash: '12345_hash', user_id: 1 }
    const databaseProvider = new DatabaseTokenProviderFactory().create(db)

    await databaseProvider.createToken(token)
    const tokens = await db.query().from('test_tokens')

    assert.lengthOf(tokens, 1)
    assert.equal(tokens[0].user_id, token.user_id)
    assert.equal(tokens[0].hash, token.hash)
    assert.equal(tokens[0].series, token.series)
  })

  test('find token by series', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const token = { series: '12345', hash: '12345_hash', user_id: 1 }
    const databaseProvider = new DatabaseTokenProviderFactory().create(db)

    await databaseProvider.createToken(token)
    const freshToken = await databaseProvider.getTokenBySeries(token.series)

    assert.deepEqual(freshToken, token)
  })

  test("return null when token doesn't exists", async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const databaseProvider = new DatabaseTokenProviderFactory().create(db)
    assert.isNull(await databaseProvider.getTokenBySeries('foobar'))
  })

  test('update token by series', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const token = { series: '12345', hash: '12345_hash', user_id: 1 }
    const databaseProvider = new DatabaseTokenProviderFactory().create(db)

    await databaseProvider.createToken(token)
    token.hash = '12345_hash_updated'
    await databaseProvider.updateTokenBySeries(token.series, token)

    const tokens = await db.query().from('test_tokens')
    assert.lengthOf(tokens, 1)
    assert.equal(tokens[0].hash, '12345_hash_updated')
  })

  test('delete token by series', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const token = { series: '12345', hash: '12345_hash', user_id: 1 }
    const databaseProvider = new DatabaseTokenProviderFactory().create(db)

    await databaseProvider.createToken(token)
    assert.isNotNull(await databaseProvider.getTokenBySeries(token.series))

    await databaseProvider.deleteTokenBySeries(token.series)
    assert.isNull(await databaseProvider.getTokenBySeries(token.series))
  })
})

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
import { RememberMeToken } from '../../../src/guards/session/remember_me_token.js'
import { DatabaseRememberTokenFactory } from '../../../factories/guards/session/database_remember_token_factory.js'

test.group('Remember me token provider', () => {
  test('persist remember me token to the database', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const token = RememberMeToken.create(1, '20mins', 'web')
    const provider = new DatabaseRememberTokenFactory().create(db)

    await provider.createToken(token)
    const tokens = await db.from('remember_me_tokens')

    assert.lengthOf(tokens, 1)
    assert.equal(tokens[0].user_id, 1)
    assert.equal(tokens[0].series, token.series)
    assert.equal(tokens[0].token, token.hash)
    assert.equal(tokens[0].guard, 'web')
    assert.equal(tokens[0].type, 'remember_me_token')
    assert.isDefined(tokens[0].created_at)
    assert.isDefined(tokens[0].updated_at)
    assert.equal(new Date(tokens[0].expires_at).getTime(), token.expiresAt.getTime())
  })

  test('get token by series', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const token = RememberMeToken.create(1, '20mins', 'web')
    const provider = new DatabaseRememberTokenFactory().create(db)

    await provider.createToken(token)
    const freshToken = (await provider.getTokenBySeries(token.series))!

    assert.instanceOf(freshToken, RememberMeToken)
    assert.equal(freshToken.series, token.series)
    assert.isUndefined(freshToken.value)
    assert.equal(freshToken.hash, token.hash)
    assert.equal(freshToken.guard, 'web')
    assert.equal(freshToken.type, 'remember_me_token')
    assert.equal(freshToken.createdAt.getTime(), token.createdAt.getTime())
    assert.equal(freshToken.updatedAt.getTime(), token.updatedAt.getTime())
    assert.equal(freshToken.expiresAt.getTime(), token.expiresAt.getTime())
  })

  test('return null when token has been expired', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const token = RememberMeToken.create(1, '20mins', 'web')
    const provider = new DatabaseRememberTokenFactory().create(db)

    await provider.createToken(token)
    timeTravel(21 * 60) // travel by 21 mins

    const freshToken = await provider.getTokenBySeries(token.series)
    assert.isNull(freshToken)
  })

  test('return null when token type mismatches', async ({ assert }) => {
    const db = await createDatabase()
    await createTables(db)

    const token = RememberMeToken.create(1, '20mins', 'web')
    const provider = new DatabaseRememberTokenFactory().create(db)

    await provider.createToken(token)

    await db.from('remember_me_tokens').where('series', token.series).update({ type: 'foo' })
    const freshToken = await provider.getTokenBySeries(token.series)
    assert.isNull(freshToken)
  })
})

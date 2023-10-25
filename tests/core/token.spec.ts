/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { TestToken } from '../../factories/database_token_factory.js'

test.group('Token', () => {
  test('create a token', ({ assert }) => {
    const token = new TestToken('1234', 'random-string', 'random-string-hash')
    assert.equal(token.series, '1234')
    assert.equal(token.value, 'random-string')
    assert.equal(token.hash, 'random-string-hash')
    assert.isDefined(token.createdAt)
    assert.isUndefined(token.expiresAt)
    assert.isUndefined(token.metaData)
    assert.equal(token.type, 'test_token')
  })

  test('create a token with seeded values', ({ assert }) => {
    const { series, value, hash } = TestToken.seed()
    const token = new TestToken(series, value, hash)
    assert.equal(token.series, series)
    assert.equal(token.value, value)
    assert.equal(token.hash, hash)
    assert.isDefined(token.createdAt)
    assert.isUndefined(token.expiresAt)
    assert.isUndefined(token.metaData)
    assert.equal(token.type, 'test_token')
  })

  test('verify value against the hash', ({ assert }) => {
    const { series, value, hash } = TestToken.seed()
    const token = new TestToken(series, value, hash)

    assert.isTrue(token.verify(TestToken.decode(value)!.value))
  })

  test('set token metadata', ({ assert }) => {
    const { series, value, hash } = TestToken.seed()
    const token = new TestToken(series, value, hash)
    token.setMetaData({ permissions: ['read-file', 'write-users'] })
    assert.deepEqual(token.metaData, { permissions: ['read-file', 'write-users'] })
  })

  test('decode valid and invalid tokens', ({ assert }) => {
    assert.isNull(TestToken.decode('foo'))
    assert.isNull(TestToken.decode('foo.bar'))

    const { series, value } = TestToken.seed()
    const decoded = TestToken.decode(value)!
    assert.equal(series, decoded.series)
  })
})

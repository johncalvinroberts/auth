/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { createHash } from 'node:crypto'
import { Secret, base64 } from '@adonisjs/core/helpers'

import { freezeTime } from '../../helpers.js'
import { RememberMeToken } from '../../../src/guards/session/remember_me_token.js'

test.group('Remember me token', () => {
  test('create a remember me token', ({ assert }) => {
    freezeTime()
    const date = new Date()
    const expiresAt = new Date()
    expiresAt.setSeconds(date.getSeconds() + 60 * 20)

    const token = RememberMeToken.create(1, '20mins', 'web')
    assert.equal(token.userId, 1)
    assert.equal(token.createdAt.getTime(), date.getTime())
    assert.equal(token.updatedAt.getTime(), date.getTime())
    assert.equal(token.expiresAt.getTime(), expiresAt.getTime())
    assert.lengthOf(token.series, 15)
    assert.instanceOf(token.value, Secret)
    assert.equal(token.guard, 'web')
    assert.equal(token.type, 'remember_me_token')
    assert.equal(
      token.hash,
      createHash('sha256')
        .update(base64.urlDecode(token.value!.release().split('.')[1])!)
        .digest('hex')
    )
  })

  test('create a remember me token from persisted data', ({ assert }) => {
    const token = RememberMeToken.createFromPersisted(1, 'web', '1234')
    assert.equal(token.series, '1234')
    assert.equal(token.userId, 1)
    assert.equal(token.guard, 'web')
    assert.equal(token.type, 'remember_me_token')
    assert.isUndefined(token.createdAt)
    assert.isUndefined(token.updatedAt)
    assert.isUndefined(token.expiresAt)
    assert.isUndefined(token.value)
    assert.isUndefined(token.hash)
  })

  test('refresh remember me token', ({ assert }) => {
    freezeTime()
    const date = new Date()
    const expiresAt = new Date()
    expiresAt.setSeconds(date.getSeconds() + 60 * 20)

    const token = RememberMeToken.createFromPersisted(1, 'web', '1234')
    token.refresh('20mins')

    /**
     * Still undefined because refresh method does not update
     * createdAt timestamp. The token providers should do
     * that
     */
    assert.isUndefined(token.createdAt)

    assert.equal(token.userId, 1)
    assert.equal(token.updatedAt.getTime(), date.getTime())
    assert.equal(token.expiresAt.getTime(), expiresAt.getTime())
    assert.equal(token.series, '1234')
    assert.instanceOf(token.value, Secret)
    assert.equal(token.guard, 'web')
    assert.equal(token.type, 'remember_me_token')
    assert.equal(
      token.hash,
      createHash('sha256')
        .update(base64.urlDecode(token.value!.release().split('.')[1])!)
        .digest('hex')
    )
  })

  test('verify token hash', ({ assert }) => {
    freezeTime()
    const date = new Date()
    const expiresAt = new Date()
    expiresAt.setSeconds(date.getSeconds() + 60 * 20)

    const token = RememberMeToken.createFromPersisted(1, 'web', '1234')
    token.refresh('20mins')
    assert.isTrue(token.verify(base64.urlDecode(token.value!.release().split('.')[1])!))
  })

  test('decode remember me token', ({ assert }) => {
    const token = RememberMeToken.create(1, '20mins', 'web')
    const { series, value } = RememberMeToken.decode(token.value!.release())!

    assert.equal(series, token.series)
    assert.isTrue(token.verify(value))
  })

  test('fail to decode invalid values', ({ assert }) => {
    assert.isNull(RememberMeToken.decode(null as any))
    assert.isNull(RememberMeToken.decode(''))
    assert.isNull(RememberMeToken.decode('...'))
    assert.isNull(RememberMeToken.decode('foobar'))
    assert.isNull(RememberMeToken.decode('foo.bar'))
  })
})

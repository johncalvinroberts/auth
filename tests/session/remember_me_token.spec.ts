/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { setTimeout } from 'node:timers/promises'
import { Secret, base64 } from '@adonisjs/core/helpers'

import { freezeTime } from '../helpers.js'
import { RememberMeToken } from '../../modules/session_guard/remember_me_token.js'

test.group('Remember me token', () => {
  test('create a remember me token', ({ assert }) => {
    freezeTime()
    const date = new Date()
    const expiresAt = new Date()
    expiresAt.setSeconds(date.getSeconds() + 60 * 20)

    const token = RememberMeToken.create(1, '20mins')
    assert.equal(token.userId, 1)
    assert.equal(token.createdAt.getTime(), date.getTime())
    assert.equal(token.updatedAt.getTime(), date.getTime())
    assert.equal(token.expiresAt.getTime(), expiresAt.getTime())
    assert.lengthOf(token.series, 15)
    assert.instanceOf(token.value, Secret)
    assert.isTrue(token.verify(RememberMeToken.decode(token.value!.release())!.value))
    assert.isFalse(token.isExpired())
  })

  test('create token from persisted information', ({ assert }) => {
    const createdAt = new Date()
    const updatedAt = new Date()
    const expiresAt = new Date()
    expiresAt.setSeconds(createdAt.getSeconds() + 60 * 20)

    const token = RememberMeToken.createFromPersisted({
      userId: 1,
      hash: '1234',
      createdAt,
      updatedAt,
      expiresAt,
      series: '1',
    })

    assert.equal(token.series, '1')
    assert.equal(token.hash, '1234')
    assert.equal(token.userId, 1)
    assert.equal(token.userId, 1)
    assert.equal(token.createdAt.getTime(), createdAt.getTime())
    assert.equal(token.updatedAt.getTime(), updatedAt.getTime())
    assert.equal(token.expiresAt.getTime(), expiresAt.getTime())
    assert.isUndefined(token.value)
    assert.isFalse(token.isExpired())
  })

  test('refresh remember me token', async ({ assert }) => {
    const createdAt = new Date()
    const updatedAt = new Date()
    const expiresAt = new Date()
    expiresAt.setSeconds(createdAt.getSeconds() + 60 * 20)

    const token = RememberMeToken.createFromPersisted({
      userId: 1,
      hash: '1234',
      createdAt,
      updatedAt,
      expiresAt,
      series: '1',
    })

    await setTimeout(100)
    token.refresh('20mins')

    assert.isDefined(token.value)
    assert.notEqual(token.hash, '1234')
    assert.isAbove(token.updatedAt.getTime(), updatedAt.getTime())
    assert.equal(token.expiresAt.getTime(), token.updatedAt.getTime() + 60 * 20 * 1000)
  })

  test('verify token hash', ({ assert }) => {
    freezeTime()
    const date = new Date()
    const expiresAt = new Date()
    expiresAt.setSeconds(date.getSeconds() + 60 * 20)

    const token = RememberMeToken.create(1, '20mins')
    assert.isTrue(token.verify(base64.urlDecode(token.value!.release().split('.')[1])!))
  })

  test('decode remember me token', ({ assert }) => {
    const token = RememberMeToken.create(1, '20mins')
    const { series, value } = RememberMeToken.decode(token.value!.release())!

    assert.equal(series, token.series)
    assert.isTrue(token.verify(value))
  })

  test('decode "{input}" as token')
    .with([
      {
        input: null,
        output: null,
      },
      {
        input: '',
        output: null,
      },
      {
        input: '..',
        output: null,
      },
      {
        input: 'foobar',
        output: null,
      },
      {
        input: 'foo.bar',
        output: null,
      },
      {
        input: 'baz.foo',
        output: null,
      },
      {
        input: `bar.${base64.urlEncode('baz')}`,
        output: null,
      },
      {
        input: `${base64.urlEncode('bar')}.baz`,
        output: null,
      },
      {
        input: `${base64.urlEncode('bar')}.${base64.urlEncode('baz')}`,
        output: {
          series: 'bar',
          value: 'baz',
        },
      },
    ])
    .run(({ assert }, { input, output }) => {
      assert.deepEqual(RememberMeToken.decode(input as string), output)
    })
})

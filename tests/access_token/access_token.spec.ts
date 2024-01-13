/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { Secret, base64 } from '@poppinss/utils'

import { timeTravel } from '../helpers.js'
import { AccessToken } from '../../modules/access_token_guard/access_token.js'

test.group('AccessToken token | decode', () => {
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
        input: 'foo.baz',
        output: null,
      },
      {
        input: 'foo_baz.foo',
        output: null,
      },
      {
        input: `api_bar.${base64.urlEncode('baz')}`,
        output: null,
      },
      {
        input: `api_${base64.urlEncode('baz')}.bar`,
        output: null,
      },
      {
        input: `api_${base64.urlEncode('baz')}.${base64.urlEncode('baz')}`,
        output: null,
      },
      {
        input: `auth_token_`,
        output: null,
      },
      {
        input: `auth_token_..`,
        output: null,
      },
      {
        input: `auth_token_foo.bar`,
        output: null,
      },
      {
        input: `auth_token_${base64.urlEncode('bar')}.${base64.urlEncode('baz')}`,
        output: {
          identifier: 'bar',
          seed: 'baz',
        },
      },
    ])
    .run(({ assert }, { input, output }) => {
      assert.deepEqual(AccessToken.decode('auth_token_', input as string), output)
    })
})

test.group('AccessToken token | create', () => {
  test('create new token', ({ assert }) => {
    const token = AccessToken.create('1', '20mins', 'auth_tokens_')

    assert.exists(token.hash)
    assert.exists(token.value)
    assert.instanceOf(token.value, Secret)
    assert.instanceOf(token.createdAt, Date)
    assert.instanceOf(token.updatedAt, Date)
    assert.instanceOf(token.expiresAt, Date)
    assert.isTrue(token.verify(AccessToken.decode('auth_tokens_', token.value!.release())!.seed))
  })

  test('decode generated token', ({ assert }) => {
    const token = AccessToken.create('1', '20mins', 'auth_tokens_')
    const { seed, identifier } = AccessToken.decode('auth_tokens_', token.value!.release())!

    assert.equal(identifier, token.identifier)
    assert.isTrue(token.verify(seed))
  })

  test('check if token has been expired', ({ assert }) => {
    const token = AccessToken.create('1', '20mins', 'auth_tokens')
    assert.isFalse(token.isExpired())

    timeTravel(21 * 60)
    assert.isTrue(token.isExpired())
  })
})

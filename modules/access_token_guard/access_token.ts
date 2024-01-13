/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { createHash } from 'node:crypto'
import string from '@adonisjs/core/helpers/string'
import { Secret, base64, safeEqual } from '@adonisjs/core/helpers'
import { CRC32 } from './crc32.js'

/**
 * Access token represents a token created for a user
 * to authenticate using the auth module.
 *
 * It encapsulates the logic of creating an opaque token, generating
 * its hash and verifying its hash.
 */
export class AccessToken {
  /**
   * Decodes a publicly shared token and return the series
   * and the token value from it.
   *
   * Returns null when unable to decode the token because of
   * invalid format or encoding.
   */
  static decode(prefix: string, value: string): null | { identifier: string; seed: string } {
    if (typeof value !== 'string' || !value.startsWith(`${prefix}`)) {
      return null
    }

    /**
     * Remove prefix from the rest of the token. For example
     * api_somerandomvalue will be converted to
     * [api, somerandomvalue]
     */
    const token = value.replace(new RegExp(`^${prefix}`), '')
    if (!token) {
      return null
    }

    /**
     * Split the token to read the identifier and the seed.
     */
    const [identifier, ...seed] = token.split('.')
    if (!identifier || seed.length === 0) {
      return null
    }

    /**
     * Decode both the base64 encoded values
     */
    const decodedIdentifer = base64.urlDecode(identifier)
    const decodedSeed = base64.urlDecode(seed.join('.'))
    if (!decodedIdentifer || !decodedSeed) {
      return null
    }

    return {
      identifier: decodedIdentifer,
      seed: decodedSeed,
    }
  }

  /**
   * Creates a new access token instance. Calling this
   * method computes the token value, hash and
   * timestamps
   */
  static create(identifier: string, expiry: string | number, prefix: string, size: number = 40) {
    const seed = AccessToken.seed(size)
    const createdAt = new Date()
    const updatedAt = new Date()
    const expiresAt = new Date()
    expiresAt.setSeconds(createdAt.getSeconds() + string.seconds.parse(expiry))

    const token = new AccessToken({
      identifier,
      hash: AccessToken.hash(seed),
      createdAt,
      updatedAt,
      expiresAt,
    })

    token.value = new Secret(`${prefix}${base64.urlEncode(identifier)}.${base64.urlEncode(seed)}`)
    return token
  }

  /**
   * Generates hash for a value. Overwrite this method to customize
   * hashing algo.
   */
  static hash(value: string) {
    return createHash('sha256').update(value).digest('hex')
  }

  /**
   * Creates a random string for an opaque token. You can override this
   * method to customize token value generation.
   */
  static seed(size: number) {
    const seed = string.random(size)
    return `${seed}${new CRC32().calculate(seed)}`
  }

  /**
   * Identifier is a unique value that can be used
   * to identify a token inside a persistance layer.
   *
   * The identifer should not have "." inside it.
   */
  identifier: string

  /**
   * Value is a combination of the "prefix""identifier"."seed"
   * The value is shared with the user and later decoded to find and
   * verify token validity
   */
  value?: Secret<string>

  /**
   * Hash is computed from the seed to later verify the validify
   * of seed
   */
  hash: string

  /**
   * Date/time when the token instance was created
   */
  createdAt: Date

  /**
   * Date/time when the token was updated
   */
  updatedAt: Date

  /**
   * Timestamp at which the token will expire
   */
  expiresAt: Date

  constructor(attributes: {
    identifier: string
    hash: string
    createdAt: Date
    updatedAt: Date
    expiresAt: Date
  }) {
    this.identifier = attributes.identifier
    this.hash = attributes.hash
    this.createdAt = attributes.createdAt
    this.updatedAt = attributes.updatedAt
    this.expiresAt = attributes.expiresAt
  }

  /**
   * Check if the token has been expired. Verifies
   * the "expiresAt" timestamp with the current
   * date.
   */
  isExpired() {
    return this.expiresAt < new Date()
  }

  /**
   * Verifies the value of a token against the pre-defined hash
   */
  verify(value: string): boolean {
    const newHash = createHash('sha256').update(value).digest('hex')
    return safeEqual(this.hash, newHash)
  }
}

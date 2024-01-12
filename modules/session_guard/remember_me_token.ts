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

/**
 * Remember me token represents a remember me token created
 * for a peristed login flow.
 */
export class RememberMeToken {
  /**
   * Decodes a publicly shared token and return the series
   * and the token value from it.
   *
   * Returns null when unable to decode the token because of
   * invalid format or encoding.
   */
  static decode(value: string): null | { series: string; value: string } {
    if (typeof value !== 'string') {
      return null
    }

    const [series, ...tokenValue] = value.split('.')
    if (!series || tokenValue.length === 0) {
      return null
    }

    const decodedSeries = base64.urlDecode(series)
    const decodedValue = base64.urlDecode(tokenValue.join('.'))
    if (!decodedSeries || !decodedValue) {
      return null
    }

    return {
      series: decodedSeries,
      value: decodedValue,
    }
  }

  /**
   * Creates remember me token instance from persisted information.
   */
  static createFromPersisted(attributes: {
    series: string
    userId: string | number | BigInt
    hash: string
    guard: string
    createdAt: Date
    updatedAt: Date
    expiresAt: Date
  }) {
    return new RememberMeToken(attributes)
  }

  /**
   * Creates a new remember me token instance. Calling this
   * method computes the token series, value, hash and
   * timestamps
   */
  static create(
    userId: string | number | BigInt,
    expiry: string | number,
    guard: string,
    size: number = 30
  ) {
    const series = string.random(15)
    const seed = string.random(size)
    const createdAt = new Date()
    const updatedAt = new Date()
    const expiresAt = new Date()
    expiresAt.setSeconds(createdAt.getSeconds() + string.seconds.parse(expiry))

    const token = new RememberMeToken({
      series,
      userId,
      hash: createHash('sha256').update(seed).digest('hex'),
      guard,
      createdAt,
      updatedAt,
      expiresAt,
    })

    token.value = new Secret(`${base64.urlEncode(token.series)}.${base64.urlEncode(seed)}`)
    return token
  }

  /**
   * Static name for the token to uniquely identify a
   * bucket of tokens
   */
  readonly type: 'remember_me_token' = 'remember_me_token'

  /**
   * Series is a unique sequence to identify the
   * token within database. It should be the
   * primary/unique key
   */
  series: string

  /**
   * Reference to the user id for whom the token
   * is generated
   */
  userId: string | number | BigInt

  /**
   * The series and seed is persisted inside the cookie and later
   * splitted to perform the lookup.
   */
  value?: Secret<string>

  /**
   * Hash is computed from the seed to later verify the validify
   * of seed
   */
  hash: string

  /**
   * Guard for which the token is generated. This is to avoid
   * cross guards using each others remember me tokens
   */
  guard: string

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
    series: string
    userId: string | number | BigInt
    hash: string
    guard: string
    createdAt: Date
    updatedAt: Date
    expiresAt: Date
  }) {
    this.series = attributes.series
    this.userId = attributes.userId
    this.hash = attributes.hash
    this.guard = attributes.guard
    this.createdAt = attributes.createdAt
    this.updatedAt = attributes.updatedAt
    this.expiresAt = attributes.expiresAt
  }

  /**
   * Refreshes the token's value, hash, updatedAt and
   * expiresAt timestamps
   */
  refresh(expiry: string | number, size: number = 30) {
    const seed = string.random(size)

    /**
     * Re-computing public value and hash
     */
    this.hash = createHash('sha256').update(seed).digest('hex')
    this.value = new Secret(`${base64.urlEncode(this.series)}.${base64.urlEncode(seed)}`)

    /**
     * Updating expiry and updated_at timestamp
     */
    this.updatedAt = new Date()
    this.expiresAt = new Date()
    this.expiresAt.setSeconds(this.updatedAt.getSeconds() + string.seconds.parse(expiry))
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

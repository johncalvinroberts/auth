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
import { base64, safeEqual } from '@adonisjs/core/helpers'

import * as errors from '../errors.js'
import type { TokenContract } from './types.js'

/**
 * A token represents an opaque token issued to a client
 * to perform a specific task.
 *
 * The raw value of a token is only visible at the time of
 * issuing it and one must persist hash to the database.
 */
export abstract class Token implements TokenContract {
  /**
   * Token type to uniquely identify a bucket of tokens
   */
  abstract readonly type: string

  /**
   * Arbitary meta-data associated with the token
   */
  metaData?: Record<string, any>

  /**
   * Timestamp when the token will expire
   */
  expiresAt?: Date

  /**
   * Date/time when the token instance was created
   */
  createdAt: Date = new Date()

  /**
   * Date/time when the token was updated
   */
  updatedAt: Date = new Date()

  constructor(
    /**
     * Series is a random number stored inside the database as it is
     */
    public series: string,

    /**
     * Value is a random number only available at the time of issuing
     * the token. Afterwards, the value is undefined.
     */
    public value: string | undefined,

    /**
     * Hash reference to the token hash
     */
    public hash: string
  ) {}

  /**
   * Define metadata for the token
   */
  setMetaData(metaData: Record<string, any>): this {
    this.metaData = metaData
    return this
  }

  /**
   * Verifies the value of a token against the pre-defined hash
   */
  verify(value: string) {
    const newHash = createHash('sha256').update(value).digest('hex')
    return safeEqual(this.hash, newHash)
  }

  /**
   * Define the token expiresAt timestamp from a duration. The value
   * value must be a number in seconds or a string expression.
   */
  setExpiry(duration: string | number) {
    /**
     * Defining a date object and adding seconds since the
     * creation of the token
     */
    this.expiresAt = new Date()
    this.expiresAt.setSeconds(this.createdAt.getSeconds() + string.seconds.parse(duration))
  }

  /**
   * Creates token value, series, and hash
   */
  static seed(size: number = 30) {
    const series = string.random(15)
    const value = string.random(size)
    const hash = createHash('sha256').update(value).digest('hex')

    return { series, value: `${base64.urlEncode(series)}.${base64.urlEncode(value)}`, hash }
  }

  /**
   * Decodes a publicly shared token and return the series
   * and the token value from it.
   */
  static decode(value: string) {
    const [series, ...tokenValue] = value.split('.')
    if (!series || tokenValue.length === 0) {
      throw new errors.E_INVALID_AUTH_TOKEN()
    }

    const decodedSeries = base64.urlDecode(series)
    const decodedValue = base64.urlDecode(tokenValue.join('.'))
    if (!decodedSeries || !decodedValue) {
      throw new errors.E_INVALID_AUTH_TOKEN()
    }

    return {
      series: decodedSeries,
      value: decodedValue,
    }
  }
}

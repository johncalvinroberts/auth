/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Token } from '../../core/token.js'

/**
 * Opaque tokens are generated to authenticate users via stateless tokens.
 */
export class OpaqueToken extends Token {
  /**
   * Static name for the token to uniquely identify a
   * bucket of tokens
   */
  readonly type: 'opaque_token' = 'opaque_token'

  /**
   * Timestamp at which the token will expire
   */
  declare expiresAt: Date

  /**
   * The guard for which the opaque token was generated
   */
  declare guard: string

  constructor(
    /**
     * Reference to the user id for whom the token
     * is generated
     */
    public userId: string | number,

    /**
     * Series is a random value stored inside the database as it is.
     * The series is generated via the seed method
     */
    public series: string,

    /**
     * Value is a random value only available at the time of issuing
     * the token. Afterwards, the value is undefined.
     */
    public value: string | undefined,

    /**
     * Hash reference to the token hash
     */
    public hash: string
  ) {
    super(series, value, hash)
  }

  /**
   * Create an opaque token for a user
   */
  static create(
    userId: string | number,
    expiry: string | number,
    guard: string,
    size?: number
  ): OpaqueToken {
    const { series, value, hash } = this.seed(size)
    const token = new OpaqueToken(userId, series, value, hash)
    token.guard = guard
    token.setExpiry(expiry)

    return token
  }
}

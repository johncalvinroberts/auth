/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Token } from '../core/token.js'
import { RememberMeTokenContract } from './types.js'

/**
 * Remember me token represents a remember me token created
 * for a peristed login flow.
 */
export class RememberMeToken extends Token implements RememberMeTokenContract {
  /**
   * Static name for the token to uniquely identify a
   * bucket of tokens
   */
  readonly type: 'remember_me_token' = 'remember_me_token'

  /**
   * Timestamp at which the token will expire
   */
  declare expiresAt: Date

  constructor(
    /**
     * Reference to the user id for whom the token
     * is generated
     */
    public userId: string | number,

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
  ) {
    super(series, value, hash)
  }

  /**
   * Create remember me token instance for a user
   */
  static create(userId: string | number, expiry: string | number, size?: number): RememberMeToken {
    const { series, value, hash } = this.seed(size)
    const token = new RememberMeToken(userId, series, value, hash)
    token.setExpiry(expiry)

    return token
  }
}

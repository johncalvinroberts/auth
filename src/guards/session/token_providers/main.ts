/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { RememberMeToken } from '../token.js'
import type { RememberMeProviderContract } from '../types.js'
import { DatabaseTokenProvider } from '../../../core/token_providers/database.js'

/**
 * Remember me token provider to persist tokens inside the database
 * using db query builder.
 */
export class DatabaseRememberTokenProvider
  extends DatabaseTokenProvider<RememberMeToken>
  implements RememberMeProviderContract
{
  /**
   * Prepares a token from the database result
   */
  protected prepareToken(dbRow: {
    series: string
    user_id: string | number
    type: string
    token: string
    created_at: Date
    updated_at: Date
    expires_at: Date | null
  }): RememberMeToken {
    const token = new RememberMeToken(dbRow.user_id, dbRow.series, undefined, dbRow.token)
    if (dbRow.expires_at) {
      token.expiresAt = dbRow.expires_at
    }
    token.createdAt = dbRow.created_at
    token.updatedAt = dbRow.updated_at

    return token
  }

  /**
   * Converts the remember me token into a database row
   */
  protected parseToken(token: RememberMeToken): {
    series: string
    user_id: string | number
    type: string
    token: string
    created_at: Date
    updated_at: Date
    expires_at: Date | null
  } {
    return {
      series: token.series,
      user_id: token.userId,
      type: token.type,
      token: token.hash,
      created_at: token.createdAt,
      updated_at: token.updatedAt,
      expires_at: token.expiresAt,
    }
  }
}

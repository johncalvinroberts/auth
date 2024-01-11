/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { RememberMeToken } from '../remember_me_token.js'
import type { RememberMeProviderContract } from '../types.js'
import { DatabaseTokenProvider } from '../../../core/token_providers/database.js'

/**
 * Representation of token within the database table
 */
type DatabaseTokenRow = {
  series: string
  user_id: string | number
  type: string
  guard: string
  token: string
  created_at: Date
  updated_at: Date
  expires_at: Date
}

/**
 * Remember me token provider to persist tokens inside the database
 * using db query builder.
 */
export class DatabaseRememberTokenProvider
  extends DatabaseTokenProvider<DatabaseTokenRow, RememberMeToken>
  implements RememberMeProviderContract
{
  /**
   * Prepares a token from the database result
   */
  protected prepareToken(dbRow: DatabaseTokenRow): RememberMeToken | null {
    const token = RememberMeToken.createFromPersisted(dbRow.user_id, dbRow.guard, dbRow.series)
    token.hash = dbRow.token
    token.guard = dbRow.guard
    token.createdAt =
      typeof dbRow.created_at === 'number' ? new Date(dbRow.created_at) : dbRow.created_at
    token.updatedAt =
      typeof dbRow.updated_at === 'number' ? new Date(dbRow.updated_at) : dbRow.updated_at
    token.expiresAt =
      typeof dbRow.expires_at === 'number' ? new Date(dbRow.expires_at) : dbRow.expires_at

    /**
     * Ensure the token fetched from db is of same type. Otherwise
     * return null
     */
    if (dbRow.type !== token.type) {
      return null
    }

    /**
     * Ensure the token is not expired
     */
    if (token.expiresAt < new Date()) {
      return null
    }

    return token
  }

  /**
   * Converts the remember me token into a database row
   */
  protected parseToken(token: RememberMeToken): DatabaseTokenRow {
    return {
      series: token.series,
      user_id: token.userId,
      type: token.type,
      token: token.hash,
      guard: token.guard,
      created_at: token.createdAt,
      updated_at: token.updatedAt,
      expires_at: token.expiresAt,
    }
  }
}

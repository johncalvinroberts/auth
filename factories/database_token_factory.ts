/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Database } from '@adonisjs/lucid/database'
import { Token } from '../src/core/token.js'
import { DatabaseTokenProvider } from '../src/core/token_providers/database.js'

/**
 * Representation of token used for testing
 */
export class TestToken extends Token {
  type = 'test_token'

  declare userId: string | number

  static create(userId: number | string, expiry: string | number, size?: number): TestToken {
    const { series, value, hash } = this.seed(size)
    const token = new TestToken(series, value, hash)
    token.setExpiry(expiry)
    token.userId = userId

    return token
  }
}

/**
 * Test implementation of the database token provider
 */
export class TestDatabaseTokenProvider extends DatabaseTokenProvider<TestToken> {
  protected prepareToken(dbRow: {
    series: string
    user_id: string | number
    type: string
    token: string
    created_at: Date
    expires_at: Date | null
  }): TestToken {
    const token = new TestToken(dbRow.series, undefined, dbRow.token)
    token.createdAt = dbRow.created_at
    if (dbRow.expires_at) {
      token.expiresAt = dbRow.expires_at
    }
    return token
  }

  protected parseToken(token: TestToken): {
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
      updated_at: token.createdAt,
      expires_at: token.expiresAt || null,
    }
  }
}

export class DatabaseTokenProviderFactory {
  create(db: Database) {
    return new TestDatabaseTokenProvider(db, {
      table: 'remember_me_tokens',
    })
  }
}

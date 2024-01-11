/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Database } from '@adonisjs/lucid/database'
import { DatabaseTokenProvider } from '../../src/core/token_providers/database.js'

type TestToken = {
  series: string
  user_id: number
  hash: string
}

/**
 * Test implementation of the database token provider
 */
export class TestDatabaseTokenProvider extends DatabaseTokenProvider<TestToken, TestToken> {
  protected prepareToken(dbRow: TestToken): TestToken {
    return dbRow
  }

  protected parseToken(token: TestToken): TestToken {
    return token
  }
}

/**
 * Creates instance of the TestDatabaseTokenProvider
 */
export class DatabaseTokenProviderFactory {
  create(db: Database) {
    return new TestDatabaseTokenProvider(db, {
      table: 'test_tokens',
    })
  }
}

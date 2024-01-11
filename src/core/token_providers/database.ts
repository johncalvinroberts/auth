/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { Database } from '@adonisjs/lucid/database'

import debug from '../../auth/debug.js'
import type { DatabaseTokenProviderOptions, TokenProviderContract } from '../types.js'

/**
 * A generic implementation to read tokens from the database
 */
export abstract class DatabaseTokenProvider<DatabaseTokenRow extends Record<string, any>, Token>
  implements TokenProviderContract<Token>
{
  constructor(
    /**
     * Reference to the database query builder needed to
     * query the database for tokens
     */
    protected db: Database,

    /**
     * Options accepted
     */
    protected options: DatabaseTokenProviderOptions
  ) {
    debug('db_token_provider: options %O', options)
  }

  /**
   * Should parse token to a database token row
   */
  protected abstract parseToken(token: Token): DatabaseTokenRow

  /**
   * Abstract method to prepare a token from the database
   * row
   */
  protected abstract prepareToken(dbRow: DatabaseTokenRow): Token | null

  /**
   * Returns an instance of the query builder
   */
  protected getQueryBuilder() {
    return this.db.connection(this.options.connection).query<DatabaseTokenRow>()
  }

  /**
   * Returns an instance of the query builder for insert
   * queries
   */
  protected getInsertQueryBuilder() {
    return this.db.connection(this.options.connection).insertQuery()
  }

  /**
   * Persists token inside the database
   */
  async createToken(token: Token): Promise<void> {
    const parsedToken = this.parseToken(token)
    debug('db_token_provider: creating token %O', parsedToken)

    await this.getInsertQueryBuilder()
      .table(this.options.table)
      .insert({
        ...parsedToken,
      })
  }

  /**
   * Finds a token by series inside the database and returns an
   * instance of it.
   *
   * Returns null if the token is missing or expired
   */
  async getTokenBySeries(series: string): Promise<Token | null> {
    debug('db_token_provider: reading token by series %s', series)
    const token = await this.getQueryBuilder()
      .from(this.options.table)
      .where('series', series)
      .limit(1)
      .first()

    if (!token) {
      debug('db_token_provider: cannot find token for series %s', series)
      return null
    }

    debug('db_token_provider: token found %O', token)
    return this.prepareToken(token)
  }

  /**
   * Removes a token from the database by the
   * series number
   */
  async deleteTokenBySeries(series: string): Promise<void> {
    debug('db_token_provider: deleting token by series %s', series)
    await this.getQueryBuilder().from(this.options.table).where('series', series).del()
  }

  /**
   * Updates token hash and expiry
   */
  async updateTokenBySeries(series: string, token: Token): Promise<void> {
    const parsedToken = this.parseToken(token)

    debug('db_token_provider: updating token by series %s: %O', series, parsedToken)

    await this.getQueryBuilder()
      .from(this.options.table)
      .where('series', series)
      .update({ ...parsedToken })
  }
}

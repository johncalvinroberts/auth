/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { Database } from '@adonisjs/lucid/database'

import debug from '../../debug.js'
import type { DatabaseTokenProviderOptions, TokenProviderContract } from '../types.js'

/**
 * The representation of a token inside the database
 */
type DatabaseTokenRow = {
  series: string
  user_id: string | number
  type: string
  token: string
  created_at: Date
  updated_at: Date
  expires_at: Date | null
}

/**
 * A generic implementation to read tokens from the database
 */
export abstract class DatabaseTokenProvider<Token> implements TokenProviderContract<Token> {
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
  protected abstract prepareToken(dbRow: DatabaseTokenRow): Token

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
      debug('db_token_provider:: token %O', token)
      return null
    }

    if (typeof token.expires_at === 'number') {
      token.expires_at = new Date(token.expires_at)
    }
    if (typeof token.created_at === 'number') {
      token.created_at = new Date(token.created_at)
    }
    if (typeof token.updated_at === 'number') {
      token.updated_at = new Date(token.updated_at)
    }

    debug('db_token_provider:: token %O', token)

    /**
     * Return null when token has been expired
     */
    if (token.expires_at && token.expires_at instanceof Date && token.expires_at < new Date()) {
      return null
    }

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
  async updateTokenBySeries(series: string, hash: string, expiresAt: Date): Promise<void> {
    const updatePayload = {
      token: hash,
      updated_at: new Date(),
      expires_at: expiresAt,
    }

    debug('db_token_provider: updating token by series %s: %O', series, updatePayload)

    await this.getQueryBuilder()
      .from(this.options.table)
      .where('series', series)
      .update(updatePayload)
  }
}

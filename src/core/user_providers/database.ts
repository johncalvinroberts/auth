/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { Hash } from '@adonisjs/core/hash'
import { RuntimeException } from '@poppinss/utils'
import type { Database } from '@adonisjs/lucid/database'

import debug from '../../debug.js'
import { GuardUser } from '../guard_user.js'
import { PROVIDER_REAL_USER } from '../../symbols.js'
import type { DatabaseUserProviderOptions, UserProviderContract } from '../types.js'

/**
 * Database user represents a guard user used by authentication guards
 * to perform authentication.
 */
class DatabaseUser<RealUser extends Record<string, any>> extends GuardUser<RealUser> {
  #options: { id: string; passwordColumnName: string }
  #hasher: Hash

  constructor(
    realUser: RealUser,
    hasher: Hash,
    options: { id: string; passwordColumnName: string }
  ) {
    super(realUser)
    this.#hasher = hasher
    this.#options = options
  }

  /**
   * @inheritdoc
   */
  getId(): string | number {
    const id = this.realUser[this.#options.id]

    if (!id) {
      throw new RuntimeException(
        `Invalid user object. The value of column "${this.#options.id}" is undefined or null`
      )
    }

    return id
  }

  /**
   * @inheritdoc
   */
  async verifyPassword(plainTextPassword: string): Promise<boolean> {
    const password = this.realUser[this.#options.passwordColumnName]

    if (!password) {
      throw new RuntimeException(
        `Cannot verify password during login. The value of column "${
          this.#options.passwordColumnName
        }" is undefined or null`
      )
    }

    return this.#hasher.verify(password, plainTextPassword)
  }
}

/**
 * Database user provider is used to lookup user for authentication
 * using the Database query builder.
 */
export abstract class DatabaseUserProvider<RealUser extends Record<string, any>>
  implements UserProviderContract<RealUser>
{
  declare [PROVIDER_REAL_USER]: RealUser

  constructor(
    /**
     * Reference to the database query builder needed to
     * query the database for users
     */
    protected db: Database,

    /**
     * Hasher is used to verify plain text passwords
     */
    protected hasher: Hash,

    /**
     * Options accepted
     */
    protected options: DatabaseUserProviderOptions<RealUser>
  ) {
    debug('db_user_provider: options %O', options)
  }

  /**
   * Returns an instance of the query builder
   */
  protected getQueryBuilder() {
    return this.db.connection(this.options.connection).query()
  }

  /**
   * Returns an instance of the "DatabaseUser" that guards
   * can use for authentication
   */
  async createUserForGuard(user: RealUser) {
    if (!user || typeof user !== 'object') {
      throw new RuntimeException(
        `Invalid user object. It must be a database row object from the "${this.options.table}" table`
      )
    }

    debug('db_user_provider: converting user object to guard user %O', user)
    return new DatabaseUser(user, this.hasher, this.options)
  }

  /**
   * Finds a user by id by query the configured database
   * table
   */
  async findById(value: string | number): Promise<DatabaseUser<RealUser> | null> {
    const query = this.getQueryBuilder().from(this.options.table)
    debug('db_user_provider: finding user by id %s', value)

    const user = await query.where(this.options.id, value).limit(1).first()
    if (!user) {
      return null
    }

    return this.createUserForGuard(user)
  }

  /**
   * Finds a user using one of the pre-configured unique
   * ids, via the configured model.
   */
  async findByUid(value: string | number): Promise<DatabaseUser<RealUser> | null> {
    const query = this.getQueryBuilder().from(this.options.table)
    this.options.uids.forEach((uid) => query.orWhere(uid, value))

    debug('db_user_provider: finding user by uids, uids: %O, value: %s', this.options.uids, value)

    const user = await query.limit(1).first()
    if (!user) {
      return null
    }

    return this.createUserForGuard(user)
  }
}

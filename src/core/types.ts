/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { QueryClientContract } from '@adonisjs/lucid/types/database'

import type { GuardUser } from './guard_user.js'
import type { PROVIDER_REAL_USER } from '../symbols.js'
import type { LucidModel, LucidRow } from '@adonisjs/lucid/types/model'

/**
 * A token represents an opaque token issued to a client
 * to perform a specific task.
 *
 * The raw value of a token is only visible at the time of
 * issuing it and one must persist hash to the database.
 */
export interface TokenContract {
  /**
   * Token type to uniquely identify a bucket of tokens
   */
  readonly type: string

  /**
   * The plain text value. Only exists when the token is first
   * created
   */
  value?: string

  /**
   * Additional metadata associated with the token.
   */
  metaData?: Record<string, any>

  /**
   * The token hash for persisting the token in a database
   */
  hash: string

  /**
   * A unique readable series counter to find the token inside the
   * database.
   */
  series: string

  /**
   * Timestamp when the token was first persisted
   */
  createdAt: Date

  /**
   * Timestamp when the token was updated
   */
  updatedAt: Date

  /**
   * Timestamp when the token will expire
   */
  expiresAt?: Date

  /**
   * Verifies the raw text value against the hash
   */
  verify(value: string): boolean
}

/**
 * The UserProvider is used to lookup a user for authentication
 */
export interface UserProviderContract<RealUser> {
  [PROVIDER_REAL_USER]: RealUser

  /**
   * Creates a user object that guards can use for
   * authentication.
   */
  createUserForGuard(user: RealUser): Promise<GuardUser<RealUser>>

  /**
   * Find a user by uid. The uid could be one or multiple fields
   * to unique identify a user.
   *
   * This method is called when finding a user for login
   */
  findByUid(value: string | number): Promise<GuardUser<RealUser> | null>

  /**
   * Find a user by unique primary id. This method is called when
   * authenticating user from their session.
   */
  findById(value: string | number): Promise<GuardUser<RealUser> | null>
}

/**
 * The TokenProvider is used to lookup/persist tokens during authentication
 */
export interface TokenProviderContract<Token> {
  /**
   * Returns a token by the series counter, or null when token is
   * missing
   */
  getTokenBySeries(series: string): Promise<Token | null>

  /**
   * Deletes a token by the series counter
   */
  deleteTokenBySeries(series: string): Promise<void>

  /**
   * Updates a token by the series counter
   */
  updateTokenBySeries(series: string, hash: string, expiresAt: Date): Promise<void>

  /**
   * Creates a new token and persists it to the database
   */
  createToken(token: Token): Promise<void>
}

/**
 * A lucid model that can be used during authentication
 */
export type LucidAuthenticatable = LucidModel & {
  new (): LucidRow & {
    /**
     * Verify the plain text password against the user password
     * hash
     */
    verifyPasswordForAuth(plainTextPassword: string): Promise<boolean>
  }
}

/**
 * Options accepted by the Lucid user provider
 */
export type LucidUserProviderOptions<Model extends LucidAuthenticatable> = {
  /**
   * Optionally define the connection to use when making database
   * queries
   */
  connection?: string

  /**
   * Optionally define the query client instance to use for making
   * database queries.
   *
   * When both "connection" and "client" are defined, the client will
   * be given the preference.
   */
  client?: QueryClientContract

  /**
   * An array of uids to use when finding a user for login. Make
   * sure all fields can be used to uniquely lookup a user.
   */
  uids: Extract<keyof InstanceType<Model>, string>[]
}

/**
 * Options accepted by the Database user provider
 */
export type DatabaseUserProviderOptions<RealUser extends Record<string, any>> = {
  /**
   * Optionally define the connection to use when making database
   * queries
   */
  connection?: string

  /**
   * Database table to query to find the user
   */
  table: string

  /**
   * Column name to read the hashed password
   */
  passwordColumnName: string

  /**
   * An array of uids to use when finding a user for login. Make
   * sure all fields can be used to uniquely lookup a user.
   */
  uids: Extract<keyof RealUser, string>[]

  /**
   * The name of the id column to unique identify the user.
   */
  id: string
}

/**
 * Options accepted by the Database token provider
 */
export type DatabaseTokenProviderOptions = {
  /**
   * Optionally define the connection to use when making database
   * queries
   */
  connection?: string

  /**
   * Database table to query to find the user
   */
  table: string
}

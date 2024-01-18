/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { Secret } from '@adonisjs/core/helpers'
import type { HttpContext } from '@adonisjs/core/http'
import type { Exception } from '@adonisjs/core/exceptions'
import type { LucidModel } from '@adonisjs/lucid/types/model'

import { PROVIDER_REAL_USER } from '../../src/symbols.js'
import type { RememberMeToken } from './remember_me_token.js'

/**
 * Options accepted by the tokens provider that uses lucid
 * database service to fetch and persist tokens.
 */
export type DbRememberMeTokensProviderOptions<TokenableModel extends LucidModel> = {
  /**
   * The user model for which to generate tokens. Note, the model
   * is not used for tokens, but is used to associate a user
   * with the token
   */
  tokenableModel: TokenableModel

  /**
   * Database table to use for querying tokens.
   *
   * Defaults to "remember_me_tokens"
   */
  table?: string

  /**
   * The default expiry for all the tokens. You can also customize
   * expiry at the time of creating a token as well.
   *
   * Defaults to "2 years"
   */
  expiresIn?: string | number

  /**
   * The length for the token secret. A secret is a cryptographically
   * secure random string.
   *
   * Defaults to 40
   */
  tokenSecretLength?: number
}

/**
 * Remember me token providers are used verify a remember me
 * token during authentication
 */
export interface RememberMeTokensProviderContract<Tokenable extends LucidModel> {
  /**
   * Create a token for a given user
   */
  create(user: InstanceType<Tokenable>, expiresIn: string | number): Promise<RememberMeToken>

  /**
   * Verifies the remember me token shared as cookie and returns an
   * instance of remember me token
   */
  verify(tokenValue: Secret<string>): Promise<RememberMeToken | null>

  /**
   * Recycle an existing token by its id. Recycling tokens helps
   * detect compromised tokens.
   * https://web.archive.org/web/20130214051957/http://jaspan.com/improved_persistent_login_cookie_best_practice
   */
  recycle(
    user: InstanceType<Tokenable>,
    identifier: string | number | BigInt,
    expiresIn: string | number
  ): Promise<RememberMeToken>
}

/**
 * The database columns expected at the database level
 */
export type RememberMeTokenDbColumns = {
  /**
   * Token primary key. It can be an integer, bigInteger or
   * even a UUID or any other string based value.
   *
   * The id should not have ". (dots)" inside it.
   */
  id: number | string | BigInt

  /**
   * The user or entity for whom the token is
   * generated
   */
  tokenable_id: string | number | BigInt

  /**
   * Token hash is used to verify the token shared
   * with the user
   */
  hash: string

  /**
   * Timestamps
   */
  created_at: Date
  updated_at: Date

  /**
   * The date after which the token will be considered
   * expired.
   */
  expires_at: Date
}

/**
 * Guard user is an adapter between the user provider
 * and the guard.
 *
 * The guard is user provider agnostic and therefore it
 * needs a adapter to known some basic info about the
 * user.
 */
export type SessionGuardUser<RealUser> = {
  getId(): string | number | BigInt
  getOriginal(): RealUser
}

/**
 * The user provider used by session guard to lookup users
 * during authentication
 */
export interface SessionUserProviderContract<RealUser> {
  [PROVIDER_REAL_USER]: RealUser

  /**
   * Create a user object that acts as an adapter between
   * the guard and real user value.
   */
  createUserForGuard(user: RealUser): Promise<SessionGuardUser<RealUser>>

  /**
   * Find a user by their id.
   */
  findById(identifier: string | number | BigInt): Promise<SessionGuardUser<RealUser> | null>

  /**
   * Create a token for a given user.
   */
  createRememberToken(user: RealUser, expiresIn?: string | number): Promise<RememberMeToken>

  /**
   * Verify a token by its publicly shared value.
   */
  verifyRememberToken(tokenValue: Secret<string>): Promise<RememberMeToken | null>

  /**
   * Recycle a token for a user by the token identifier.
   */
  recycleRememberToken(
    user: RealUser,
    identifier: string | number | BigInt,
    expiresIn?: string | number
  ): Promise<RememberMeToken>

  /**
   * Delete a token for a user by the token identifier.
   */
  deleteRemeberToken(user: RealUser, identifier: string | number | BigInt): Promise<number>
}

/**
 * Events emitted by the session guard
 */
export type SessionGuardEvents<User> = {
  /**
   * The event is emitted when login is attempted for
   * a given user.
   */
  'session_auth:login_attempted': {
    ctx: HttpContext
    guardName: string
    user: User
  }

  /**
   * The event is emitted when user has been logged in
   * successfully
   */
  'session_auth:login_succeeded': {
    ctx: HttpContext
    guardName: string
    user: User
    sessionId: string
    rememberMeToken?: RememberMeToken
  }

  /**
   * Attempting to authenticate the user
   */
  'session_auth:authentication_attempted': {
    ctx: HttpContext
    guardName: string
    sessionId: string
  }

  /**
   * Authentication was successful
   */
  'session_auth:authentication_succeeded': {
    ctx: HttpContext
    guardName: string
    user: User
    sessionId: string
    rememberMeToken?: RememberMeToken
  }

  /**
   * Authentication failed
   */
  'session_auth:authentication_failed': {
    ctx: HttpContext
    guardName: string
    error: Exception
    sessionId: string
  }

  /**
   * The event is emitted when user has been logged out
   * sucessfully
   */
  'session_auth:logged_out': {
    ctx: HttpContext
    guardName: string
    user: User | null
    sessionId: string
  }
}

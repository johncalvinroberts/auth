/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { HashersList } from '@adonisjs/core/types'
import type { HttpContext } from '@adonisjs/core/http'
import { LucidModel } from '@adonisjs/lucid/types/model'
import type { Exception } from '@adonisjs/core/exceptions'
import type { HasMany } from '@adonisjs/lucid/types/relations'
import type { RememberMeTokenModel } from './models/remember_me_token.js'

import type { RememberMeToken } from './remember_me_token.js'
import type { PROVIDER_REAL_USER } from '../../src/symbols.js'

/**
 * Options accepted by the Session Lucid user provider
 */
export type SessionLucidUserProviderOptions<Model extends LucidAuthenticatable> = {
  /**
   * Define the hasher to use to hash and verify
   * passwords
   */
  hasher?: keyof HashersList

  /**
   * Optionally define the connection to use when making database
   * queries
   */
  connection?: string

  /**
   * Model to use for authentication
   */
  model: () => Promise<{ default: Model }>

  /**
   * Column name to read the hashed password
   */
  passwordColumnName: Extract<keyof InstanceType<Model>, string>

  /**
   * An array of uids to use when finding a user for login. Make
   * sure all fields can be used to uniquely lookup a user.
   */
  uids: Extract<keyof InstanceType<Model>, string>[]
}

/**
 * A lucid model that can be used during authentication
 */
export type LucidAuthenticatable = LucidModel & {
  /**
   * HasMany relationship to manage rememberMe tokens
   */
  rememberMeTokens?: HasMany<typeof RememberMeTokenModel>

  /**
   * Optional static method to customize the user lookup
   * during "findByUid" method call.
   */
  getUserForAuth?(uids: string[], value: string | number): Promise<any | null>
}

/**
 * Guard user is an adapter between the user provider
 * and the guard.
 *
 * The guard is user provider agnostic and therefore it
 * needs a adapter to known some basic info about the
 * user.
 */
export type GuardUser<RealUser> = {
  getId(): string | number | BigInt
  getOriginal(): RealUser
}

/**
 * The user provider used by the session guard to lookup
 * user and persist remember me tokens
 */
export interface SessionUserProviderContract<RealUser> {
  [PROVIDER_REAL_USER]: RealUser

  /**
   * Creates a user object that guard can use for authentication
   */
  createUserForGuard(user: RealUser): Promise<GuardUser<RealUser>>

  /**
   * Find a user by uid. The uid could be one or multiple fields
   * to unique identify a user.
   *
   * This method is called when finding a user for login
   */
  findByUid(uid: string | number): Promise<GuardUser<RealUser> | null>

  /**
   * Find a user by unique primary id. This method is called when
   * authenticating user from their session.
   */
  findById(userId: string | number | BigInt): Promise<GuardUser<RealUser> | null>

  /**
   * Find a user by uid and verify their password. This method prevents
   * timing attacks.
   */
  verifyCredentials(uid: string | number, password: string): Promise<GuardUser<RealUser> | null>

  /**
   * Persist remember me token. The userId is available via the token.userId property.
   */
  createRememberMeToken?(token: RememberMeToken): Promise<void>

  /**
   * Delete the remember token by the series value
   */
  deleteRememberMeTokenBySeries?(series: string): Promise<void>

  /**
   * Find a remember me token by the series value
   */
  findRememberMeTokenBySeries?(series: string): Promise<RememberMeToken | null>

  /**
   * Recycle the remember me token attributes. The update must be
   * performed by first finding the token by series and then
   * updating its attributes.
   */
  recycleRememberMeToken?(token: RememberMeToken): Promise<void>
}

/**
 * Config accepted by the session guard
 */
export type SessionGuardConfig = {
  rememberMeTokenAge?: number | string
}

/**
 * Events emitted by the session guard
 */
export type SessionGuardEvents<User> = {
  /**
   * The event is emitted when the user credentials
   * have been verified successfully.
   */
  'session_auth:credentials_verified': {
    ctx: HttpContext
    guardName: string
    uid: string
    user: User
  }

  /**
   * The event is emitted when unable to login the
   * user.
   */
  'session_auth:login_failed': {
    ctx: HttpContext
    guardName: string
    error: Exception
  }

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

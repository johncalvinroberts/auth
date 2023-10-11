/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Exception } from '@poppinss/utils'

import type { PROVIDER_REAL_USER } from '../core/symbols.js'
import type {
  TokenContract,
  UserProviderContract,
  TokenProviderContract,
  DatabaseTokenProviderOptions,
} from '../core/types.js'

/**
 * Representation of a remember me token
 */
export interface RememberMeTokenContract extends TokenContract {
  /**
   * Token type to uniquely identify a bucket of tokens
   */
  readonly type: 'remember_me_token'

  /**
   * Timestamp when the token will expire
   */
  expiresAt: Date

  /**
   * Reference to the user for whom the token is generated
   */
  userId: string | number
}

/**
 * The SessionUserProvider is used to lookup a user for session based authentication.
 */
export interface SessionUserProviderContract<RealUser> extends UserProviderContract<RealUser> {}

/**
 * The RememberMeProviderContract is used to persist and lookup tokens for
 * session based authentication with remember me option.
 */
export interface RememberMeProviderContract
  extends TokenProviderContract<RememberMeTokenContract> {}

/**
 * Config accepted by the session guard
 */
export type SessionGuardConfig = {
  /**
   * The expiry for the remember me cookie.
   *
   * Defaults to "5 years"
   */
  rememberMeTokenAge: string | number
}

/**
 * Events emitted by the session guard
 */
export type SessionGuardEvents<UserProvider extends SessionUserProviderContract<unknown>> = {
  /**
   * The event is emitted when the user credentials
   * have been verified successfully.
   */
  'session_auth:credentials_verified': {
    uid: string
    user: UserProvider[typeof PROVIDER_REAL_USER]
    password: string
  }

  /**
   * The event is emitted when unable to login the
   * user.
   */
  'session_auth:login_failed': {
    error: Exception
    user: UserProvider[typeof PROVIDER_REAL_USER] | null
  }

  /**
   * The event is emitted when login is attempted for
   * a given user.
   */
  'session_auth:login_attempted': {
    user: UserProvider[typeof PROVIDER_REAL_USER]
  }

  /**
   * The event is emitted when user has been logged in
   * successfully
   */
  'session_auth:login_succeeded': {
    user: UserProvider[typeof PROVIDER_REAL_USER]
    sessionId: string
    rememberMeToken?: RememberMeTokenContract
  }

  /**
   * The event is emitted when user has been logged out
   * sucessfully
   */
  'session_auth:logged_out': {
    user: UserProvider[typeof PROVIDER_REAL_USER]
    sessionId: string
  }
}

/**
 * Options accepted by the database implementation of the
 * RememberMeProvider
 */
export type DatabaseRememberMeProviderOptions = DatabaseTokenProviderOptions

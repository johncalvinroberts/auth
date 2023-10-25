/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Exception } from '@poppinss/utils'

import type { RememberMeToken } from './token.js'
import type {
  UserProviderContract,
  TokenProviderContract,
  DatabaseTokenProviderOptions,
} from '../../core/types.js'

/**
 * The SessionUserProvider is used to lookup a user for session based authentication.
 */
export interface SessionUserProviderContract<RealUser> extends UserProviderContract<RealUser> {}

/**
 * The RememberMeProviderContract is used to persist and lookup tokens for
 * session based authentication with remember me option.
 */
export interface RememberMeProviderContract extends TokenProviderContract<RememberMeToken> {}

/**
 * Config accepted by the session guard
 */
export type SessionGuardConfig = {
  /**
   * The expiry for the remember me cookie.
   *
   * Defaults to "5 years"
   */
  rememberMeTokenAge?: string | number
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
    guardName: string
    uid: string
    user: User
  }

  /**
   * The event is emitted when unable to login the
   * user.
   */
  'session_auth:login_failed': {
    guardName: string
    error: Exception
    user: User | null
  }

  /**
   * The event is emitted when login is attempted for
   * a given user.
   */
  'session_auth:login_attempted': {
    guardName: string
    user: User
  }

  /**
   * The event is emitted when user has been logged in
   * successfully
   */
  'session_auth:login_succeeded': {
    guardName: string
    user: User
    sessionId: string
    rememberMeToken?: RememberMeToken
  }

  /**
   * Attempting to authenticate the user
   */
  'session_auth:authentication_attempted': {
    guardName: string
    sessionId: string
  }

  /**
   * Authentication was successful
   */
  'session_auth:authentication_succeeded': {
    guardName: string
    user: User
    sessionId: string
    rememberMeToken?: RememberMeToken
  }

  /**
   * Authentication failed
   */
  'session_auth:authentication_failed': {
    guardName: string
    error: Exception
    sessionId: string
  }

  /**
   * The event is emitted when user has been logged out
   * sucessfully
   */
  'session_auth:logged_out': {
    guardName: string
    user: User | null
    sessionId: string
  }
}

/**
 * Options accepted by the database implementation of the
 * RememberMeProvider
 */
export type DatabaseRememberMeProviderOptions = DatabaseTokenProviderOptions

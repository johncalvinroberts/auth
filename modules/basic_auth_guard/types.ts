/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { HttpContext } from '@adonisjs/core/http'
import type { Exception } from '@adonisjs/core/exceptions'
import type { PROVIDER_REAL_USER } from '../../src/symbols.js'

/**
 * Guard user is an adapter between the user provider
 * and the guard.
 *
 * The guard is user provider agnostic and therefore it
 * needs a adapter to known some basic info about the
 * user.
 */
export type BasicAuthGuardUser<RealUser> = {
  getId(): string | number | BigInt
  getOriginal(): RealUser
}

/**
 * The user provider used by basic auth guard to lookup users
 * during authentication
 */
export interface BasicAuthUserProviderContract<RealUser> {
  [PROVIDER_REAL_USER]: RealUser

  /**
   * Create a user object that acts as an adapter between
   * the guard and real user value.
   */
  createUserForGuard(user: RealUser): Promise<BasicAuthGuardUser<RealUser>>

  /**
   * Verify user credentials and must return an instance of the
   * user back or null when the credentials are invalid
   */
  verifyCredentials(uid: string, password: string): Promise<BasicAuthGuardUser<RealUser> | null>
}

/**
 * Events emitted by the basic auth guard
 */
export type BasicAuthGuardEvents<User> = {
  /**
   * Attempting to authenticate the user
   */
  'basic_auth:authentication_attempted': {
    ctx: HttpContext
    guardName: string
  }

  /**
   * Authentication was successful
   */
  'basic_auth:authentication_succeeded': {
    ctx: HttpContext
    guardName: string
    user: User
  }

  /**
   * Authentication failed
   */
  'basic_auth:authentication_failed': {
    ctx: HttpContext
    guardName: string
    error: Exception
  }
}

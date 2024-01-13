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

import type { AccessToken } from './access_token.js'
import type { PROVIDER_REAL_USER } from '../../src/symbols.js'

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
 * User provider accepted by the Access token guard implementation
 * to find users by tokens.
 *
 * The guards are responsible for decoding and verifying tokens
 */
export interface AccessTokenUserProviderContract<RealUser> {
  [PROVIDER_REAL_USER]: RealUser

  /**
   * Create a token for a given user. The return value must be an
   * instance of an access token
   */
  createToken(user: RealUser): Promise<AccessToken>

  /**
   * Find a user from a opaque token value
   */
  findUserByToken(token: Secret<string>): Promise<GuardUser<RealUser> | null>
}

/**
 * Events emitted by the access token guard
 */
export type AccessTokenGuardEvents<User> = {
  /**
   * Attempting to authenticate the user
   */
  'access_token_auth:authentication_attempted': {
    ctx: HttpContext
    guardName: string
  }

  /**
   * Authentication was successful
   */
  'access_token_auth:authentication_succeeded': {
    ctx: HttpContext
    guardName: string
    user: User
    token: Secret<string>
  }

  /**
   * Authentication failed
   */
  'access_token_auth:authentication_failed': {
    ctx: HttpContext
    guardName: string
    error: Exception
    token?: Secret<string>
  }
}

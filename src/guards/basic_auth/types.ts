/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Exception } from '@poppinss/utils'
import type { HttpContext } from '@adonisjs/core/http'

/**
 * Events emitted by the basic auth guard
 */
export type BasicAuthGuardEvents<User> = {
  /**
   * The event is emitted when the user credentials
   * have been verified successfully.
   */
  'basic_auth:credentials_verified': {
    ctx: HttpContext
    guardName: string
    uid: string
    user: User
  }

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

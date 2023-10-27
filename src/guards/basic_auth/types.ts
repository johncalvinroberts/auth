/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Exception } from '@poppinss/utils'

/**
 * Events emitted by the basic auth guard
 */
export type BasicAuthGuardEvents<User> = {
  /**
   * The event is emitted when the user credentials
   * have been verified successfully.
   */
  'basic_auth:credentials_verified': {
    guardName: string
    uid: string
    user: User
  }

  /**
   * Attempting to authenticate the user
   */
  'basic_auth:authentication_attempted': {
    guardName: string
  }

  /**
   * Authentication was successful
   */
  'basic_auth:authentication_succeeded': {
    guardName: string
    user: User
  }

  /**
   * Authentication failed
   */
  'basic_auth:authentication_failed': {
    guardName: string
    error: Exception
  }
}

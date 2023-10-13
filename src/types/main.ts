/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { Emitter } from '@adonisjs/core/events'
import type { HttpContext } from '@adonisjs/core/http'
import { ApplicationService } from '@adonisjs/core/types'

import type { GUARD_KNOWN_EVENTS } from '../symbols.js'

/**
 * A set of properties a guard must implement.
 */
export interface GuardContract<User> {
  /**
   * Reference to the user type
   */
  user?: User

  /**
   * Aymbol for infer the events emitted by a specific
   * guard
   */
  [GUARD_KNOWN_EVENTS]: unknown

  /**
   * Accept an instance of the emitter to emit events
   */
  withEmitter(emitter: Emitter<any>): this
}

/**
 * Config providers are async function that needs app instance
 * and returns configuration
 */
export type ConfigProvider<T> = (key: string, app: ApplicationService) => Promise<T>

/**
 * The authenticator guard factory method is called by the
 * Authenticator class to create an instance of a specific
 * guard during an HTTP request
 */
export type AuthenticatorGuardFactory = (ctx: HttpContext) => GuardContract<unknown>

/**
 * Authenticators are inferred inside the user application
 * from the config file
 */
export interface Authenticators {}

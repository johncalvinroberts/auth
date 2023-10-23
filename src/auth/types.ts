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
import type { ApplicationService, ConfigProvider } from '@adonisjs/core/types'

import type { AuthManager } from './auth_manager.js'
import type { GUARD_KNOWN_EVENTS } from './symbols.js'

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
 * The authenticator guard factory method is called by the
 * Authenticator class to create an instance of a specific
 * guard during an HTTP request
 */
export type GuardFactory = (ctx: HttpContext) => GuardContract<unknown>

/**
 * Authenticators are inferred inside the user application
 * from the config file
 */
export interface Authenticators {}

/**
 * Infer authenticators from the auth config
 */
export type InferAuthenticators<Config extends ConfigProvider<unknown>> = Awaited<
  ReturnType<Config['resolver']>
>

/**
 * Auth service is a singleton instance of the AuthManager
 * configured using the config stored within the user
 * app.
 */
export interface AuthService
  extends AuthManager<Authenticators extends GuardFactory ? Authenticators : never> {}

/**
 * Config provider for exporting guard
 */
export type GuardConfigProvider<Guard extends GuardFactory> = {
  resolver: (name: string, app: ApplicationService) => Promise<Guard>
}

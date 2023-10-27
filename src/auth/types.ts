/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { HttpContext } from '@adonisjs/core/http'
import type { ApplicationService, ConfigProvider } from '@adonisjs/core/types'

import type { AuthManager } from './auth_manager.js'
import type { GUARD_KNOWN_EVENTS } from './symbols.js'

/**
 * The client response for authentication.
 */
export interface AuthClientResponse {
  headers?: Record<string, any>
  cookies?: Record<string, any>
  session?: Record<string, any>
}

/**
 * A set of properties a guard must implement.
 */
export interface GuardContract<User> {
  /**
   * Reference to the currently authenticated user
   */
  user?: User

  /**
   * Returns logged-in user or throws an exception
   */
  getUserOrFail(): User

  /**
   * A boolean to know if the current request has
   * been authenticated
   */
  isAuthenticated: boolean

  /**
   * Whether or not the authentication has been attempted
   * during the current request
   */
  authenticationAttempted: boolean

  /**
   * Check if the current request has been
   * authenticated without throwing an
   * exception
   */
  check(): Promise<boolean>

  /**
   * The method is used to authenticate the user as
   * client. This method should return cookies,
   * headers, or session state.
   */
  authenticateAsClient(user: User): Promise<AuthClientResponse>

  /**
   * Authenticates the current request and throws
   * an exception if the request is not authenticated.
   */
  authenticate(): Promise<User>

  /**
   * A unique name for the guard driver
   */
  driverName: string

  /**
   * Aymbol for infer the events emitted by a specific
   * guard
   */
  [GUARD_KNOWN_EVENTS]: unknown
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
export type InferAuthenticators<
  Config extends ConfigProvider<{
    default: unknown
    guards: unknown
  }>,
> = Awaited<ReturnType<Config['resolver']>>['guards']

/**
 * Helper to convert union to intersection
 */
type UnionToIntersection<U> = (U extends any ? (k: U) => void : never) extends (k: infer I) => void
  ? I
  : never

/**
 * Infer events based upon the configure authenticators
 */
export type InferAuthEvents<KnownAuthenticators extends Record<string, GuardFactory>> =
  UnionToIntersection<
    {
      [K in keyof KnownAuthenticators]: ReturnType<
        KnownAuthenticators[K]
      >[typeof GUARD_KNOWN_EVENTS]
    }[keyof KnownAuthenticators]
  >

/**
 * Auth service is a singleton instance of the AuthManager
 * configured using the config stored within the user
 * app.
 */
export interface AuthService
  extends AuthManager<
    Authenticators extends Record<string, GuardFactory> ? Authenticators : never
  > {}

/**
 * Config provider for exporting guard
 */
export type GuardConfigProvider<Guard extends GuardFactory> = {
  resolver: (name: string, app: ApplicationService) => Promise<Guard>
}

/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { HttpContext } from '@adonisjs/core/http'

import debug from './debug.js'
import type { GuardFactory } from './types.js'
import { AuthenticationException } from './errors.js'

/**
 * Authenticator is an HTTP request specific implementation for using
 * guards to login users and authenticate requests.
 */
export class Authenticator<KnownGuards extends Record<string, GuardFactory>> {
  /**
   * Name of the guard using which the request has
   * been authenticated
   */
  #authenticatedViaGuard?: keyof KnownGuards

  /**
   * Reference to HTTP context
   */
  #ctx: HttpContext

  /**
   * Registered guards
   */
  #config: {
    default: keyof KnownGuards
    guards: KnownGuards
  }

  /**
   * Cache of guards created during the HTTP request
   */
  #guardsCache: Partial<Record<keyof KnownGuards, unknown>> = {}

  /**
   * Name of the default guard
   */
  get defaultGuard(): keyof KnownGuards {
    return this.#config.default
  }

  /**
   * Reference to the guard using which the current
   * request has been authenticated.
   */
  get authenticatedViaGuard(): keyof KnownGuards | undefined {
    return this.#authenticatedViaGuard
  }

  /**
   * A boolean to know if the current request has
   * been authenticated
   */
  get isAuthenticated(): boolean {
    return this.use(this.#authenticatedViaGuard || this.defaultGuard).isAuthenticated
  }

  /**
   * Reference to the currently authenticated user
   */
  get user(): {
    [K in keyof KnownGuards]: ReturnType<KnownGuards[K]>['user']
  }[keyof KnownGuards] {
    return this.use(this.#authenticatedViaGuard || this.defaultGuard).user
  }

  /**
   * Whether or not the authentication has been attempted
   * during the current request
   */
  get authenticationAttempted(): boolean {
    return this.use(this.#authenticatedViaGuard || this.defaultGuard).authenticationAttempted
  }

  constructor(ctx: HttpContext, config: { default: keyof KnownGuards; guards: KnownGuards }) {
    this.#ctx = ctx
    this.#config = config
    debug('creating authenticator. config %O', this.#config)
  }

  /**
   * Returns an instance of the logged-in user or throws an
   * exception
   */
  getUserOrFail(): {
    [K in keyof KnownGuards]: ReturnType<ReturnType<KnownGuards[K]>['getUserOrFail']>
  }[keyof KnownGuards] {
    return this.use(this.#authenticatedViaGuard || this.defaultGuard).getUserOrFail() as {
      [K in keyof KnownGuards]: ReturnType<ReturnType<KnownGuards[K]>['getUserOrFail']>
    }[keyof KnownGuards]
  }

  /**
   * Returns an instance of a known guard. Guards instances are
   * cached during the lifecycle of an HTTP request.
   */
  use<Guard extends keyof KnownGuards>(guard?: Guard): ReturnType<KnownGuards[Guard]> {
    const guardToUse = guard || this.#config.default

    /**
     * Use cached copy if exists
     */
    const cachedGuard = this.#guardsCache[guardToUse]
    if (cachedGuard) {
      debug('using guard from cache. name: "%s"', guardToUse)
      return cachedGuard as ReturnType<KnownGuards[Guard]>
    }

    const guardFactory = this.#config.guards[guardToUse]

    /**
     * Construct guard and cache it
     */
    debug('creating guard. name: "%s"', guardToUse)
    const guardInstance = guardFactory(this.#ctx)
    this.#guardsCache[guardToUse] = guardInstance

    return guardInstance as ReturnType<KnownGuards[Guard]>
  }

  /**
   * Authenticate the request using all of the mentioned
   * guards or the default guard.
   *
   * The authentication process will stop after any of the
   * mentioned guards is able to authenticate the request
   * successfully.
   *
   * Otherwise, "AuthenticationException" will be raised.
   */
  async authenticateUsing(guards?: (keyof KnownGuards)[], options?: { loginRoute?: string }) {
    const guardsToUse = guards || [this.defaultGuard]
    let lastUsedGuardDriver: string | undefined

    for (let guardName of guardsToUse) {
      debug('attempting to authenticate using guard "%s"', guardName)
      const guard = this.use(guardName)
      lastUsedGuardDriver = guard.driverName

      if (await guard.check()) {
        this.#authenticatedViaGuard = guardName
        return true
      }
    }

    throw new AuthenticationException('Unauthorized access', {
      code: 'E_UNAUTHORIZED_ACCESS',
      guardDriverName: lastUsedGuardDriver!,
      redirectTo: options?.loginRoute,
    })
  }
}

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

/**
 * Authenticator is an HTTP request specific implementation for using
 * guards to login users and authenticate requests.
 */
export class Authenticator<KnownGuards extends Record<string, GuardFactory>> {
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

  constructor(ctx: HttpContext, config: { default: keyof KnownGuards; guards: KnownGuards }) {
    this.#ctx = ctx
    this.#config = config
    debug('creating authenticator. config %O', this.#config)
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
}

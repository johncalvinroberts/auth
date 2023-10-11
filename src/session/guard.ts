/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/// <reference types="@adonisjs/session/session_middleware" />

import { Emitter } from '@adonisjs/core/events'
import { RuntimeException } from '@poppinss/utils'
import type { HttpContext } from '@adonisjs/core/http'

import { PROVIDER_REAL_USER } from '../core/symbols.js'
import type {
  SessionGuardEvents,
  SessionGuardConfig,
  SessionUserProviderContract,
  RememberMeProviderContract,
} from './types.js'

export class SessionGuard<UserProvider extends SessionUserProviderContract<unknown>> {
  /**
   * A unique name for the guard. It is used for prefixing
   * session data and remember me cookies
   */
  #name: string

  /**
   * Reference to the current HTTP context
   */
  #ctx: HttpContext

  /**
   * Configuration
   */
  #config: SessionGuardConfig

  /**
   * Provider to lookup user details
   */
  #userProvider: UserProvider

  /**
   * The remember me tokens provider to use to persist
   * remember me tokens
   */
  #rememberMeTokenProvider?: RememberMeProviderContract

  /**
   * Emitter to emit events
   */
  #emitter?: Emitter<SessionGuardEvents<UserProvider>>

  /**
   * The key used to store the logged-in user id inside
   * session
   */
  get sessionKeyName() {
    return `auth_${this.#name}`
  }

  /**
   * The key used to store the remember me token cookie
   */
  get rememberMeKeyName() {
    return `remember_${this.#name}`
  }

  constructor(
    name: string,
    config: SessionGuardConfig,
    ctx: HttpContext,
    userProvider: UserProvider
  ) {
    this.#name = name
    this.#ctx = ctx
    this.#config = config
    this.#userProvider = userProvider
  }

  /**
   * Returns the session instance for the given request
   */
  #getSession() {
    if (!('session' in this.#ctx)) {
      throw new RuntimeException(
        'Cannot login user. Make sure you have installed the "@adonisjs/session" package and configured its middleware'
      )
    }

    return this.#ctx.session
  }

  /**
   * Register the remember me tokens provider to create
   * remember me tokens during user login.
   *
   * Note: This method only registers the remember me tokens provider
   * and does not enable them. You must pass "rememberMe = true" during
   * the "login" method call.
   */
  withRememberMeTokens(tokensProvider: RememberMeProviderContract): this {
    this.#rememberMeTokenProvider = tokensProvider
    return this
  }

  /**
   * Register an event emitter to listen for global events for
   * authentication lifecycle.
   */
  withEmitter(emitter: Emitter<SessionGuardEvents<UserProvider>>): this {
    this.#emitter = emitter
    return this
  }

  /**
   * Login a user using the user object.
   */
  async login(user: UserProvider[typeof PROVIDER_REAL_USER]) {
    if (this.#emitter) {
      this.#emitter.emit('session_auth:login_attempted', { user })
    }

    const providerUser = await this.#userProvider.createUserForGuard(user)
    const session = this.#getSession()

    /**
     * Create session and recycle the session id
     */
    session.put(this.sessionKeyName, providerUser.getId())
    session.regenerate()

    if (this.#emitter) {
      this.#emitter.emit('session_auth:login_succeeded', { user, sessionId: session.sessionId })
    }
  }
}

/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Secret } from '@adonisjs/core/helpers'
import type { HttpContext } from '@adonisjs/core/http'
import type { EmitterLike } from '@adonisjs/core/types/events'

import debug from './debug.js'
import { E_UNAUTHORIZED_ACCESS } from '../../src/errors.js'
import type { AuthClientResponse, GuardContract } from '../../src/types.js'
import { GUARD_KNOWN_EVENTS, PROVIDER_REAL_USER } from '../../src/symbols.js'
import type { AccessTokenGuardEvents, AccessTokenUserProviderContract } from './types.js'

/**
 * Access token guard is used to authenticate incoming HTTP requests by
 * reading the "Bearer" token from the Authorization header.
 *
 * The heavy lifting of verifying tokens and finding users is done by
 * the userProvider. The guard job is integrate seamlessly with the
 * auth layer of AdonisJS.
 */
export class AccessTokenGuard<UserProvider extends AccessTokenUserProviderContract<unknown>>
  implements GuardContract<UserProvider[typeof PROVIDER_REAL_USER]>
{
  /**
   * Events emitted by the guard
   */
  declare [GUARD_KNOWN_EVENTS]: AccessTokenGuardEvents<UserProvider[typeof PROVIDER_REAL_USER]>

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
   * Emitter to emit events
   */
  #emitter: EmitterLike<AccessTokenGuardEvents<UserProvider[typeof PROVIDER_REAL_USER]>>

  /**
   * Provider to lookup user details
   */
  #userProvider: UserProvider

  /**
   * Driver name of the guard
   */
  driverName: 'access_token' = 'access_token'

  /**
   * Whether or not the authentication has been attempted
   * during the current request.
   */
  authenticationAttempted = false

  /**
   * A boolean to know if the current request has
   * been authenticated
   */
  isAuthenticated = false

  /**
   * Reference to an instance of the authenticated user.
   * The value only exists after calling one of the
   * following methods.
   *
   * - authenticate
   * - check
   *
   * You can use the "getUserOrFail" method to throw an exception if
   * the request is not authenticated.
   */
  user?: UserProvider[typeof PROVIDER_REAL_USER]

  constructor(
    name: string,
    ctx: HttpContext,
    emitter: EmitterLike<AccessTokenGuardEvents<UserProvider[typeof PROVIDER_REAL_USER]>>,
    userProvider: UserProvider
  ) {
    this.#name = name
    this.#ctx = ctx
    this.#emitter = emitter
    this.#userProvider = userProvider
    debug('instantiating "%s" guard', this.#name)
  }

  /**
   * Emits authentication failure and returns an exception
   * to end the authentication cycle.
   */
  #authenticationFailed(token?: Secret<string>) {
    const error = new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: this.driverName,
    })

    this.#emitter.emit('access_token_auth:authentication_failed', {
      ctx: this.#ctx,
      guardName: this.#name,
      token,
      error,
    })

    return error
  }

  /**
   * Returns an instance of the authenticated user. Or throws
   * an exception if the request is not authenticated.
   */
  getUserOrFail(): UserProvider[typeof PROVIDER_REAL_USER] {
    if (!this.user) {
      throw new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    return this.user
  }

  /**
   * Authenticates the current HTTP request to contain a valid
   * bearer token inside "Authorization" header.
   *
   * The token verification is performed by the registered user
   * provider.
   */
  async authenticate(): Promise<UserProvider[typeof PROVIDER_REAL_USER]> {
    /**
     * Return early when authentication has already
     * been attempted
     */
    if (this.authenticationAttempted) {
      return this.getUserOrFail()
    }

    debug('authenticating request to contain a valid bearer token')

    /**
     * Notify we begin to attempt the authentication
     */
    this.authenticationAttempted = true
    this.#emitter.emit('access_token_auth:authentication_attempted', {
      ctx: this.#ctx,
      guardName: this.#name,
    })

    /**
     * Ensure the authorization header exists and it contains a valid
     * Bearer token.
     */
    const bearerToken = this.#ctx.request.header('authorization', '')!
    const [, token] = bearerToken.split('Bearer ')
    if (!token) {
      throw this.#authenticationFailed()
    }

    debug('found bearer token in authorization header')

    /**
     * Converting token to a secret and verify it using the provider.
     * The provider must return a user instance if token is valid.
     */
    const tokenAsSecret = new Secret(token)
    const providerUser = await this.#userProvider.findUserByToken(tokenAsSecret)
    if (!providerUser) {
      throw this.#authenticationFailed(tokenAsSecret)
    }

    debug('marking user with id "%s" as authenticated', providerUser.getId())

    /**
     * Update local state
     */
    this.isAuthenticated = true
    this.user = providerUser.getOriginal()

    /**
     * Notify
     */
    this.#emitter.emit('access_token_auth:authentication_succeeded', {
      ctx: this.#ctx,
      token: tokenAsSecret,
      guardName: this.#name,
      user: this.user,
    })

    return this.user
  }

  /**
   * Returns the Authorization header clients can use to authenticate
   * the request.
   */
  async authenticateAsClient(
    user: UserProvider[typeof PROVIDER_REAL_USER]
  ): Promise<AuthClientResponse> {
    const token = await this.#userProvider.createToken(user)
    return {
      headers: {
        Authorization: `Bearer ${token.value!.release()}`,
      },
    }
  }

  /**
   * Silently check if the user is authenticated or not, without
   * throwing any exceptions
   */
  async check(): Promise<boolean> {
    try {
      await this.authenticate()
      return true
    } catch (error) {
      if (error instanceof E_UNAUTHORIZED_ACCESS) {
        return false
      }

      throw error
    }
  }
}

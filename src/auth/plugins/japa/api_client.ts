/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/// <reference types="@adonisjs/session/plugins/api_client" />

import { ApiClient, ApiRequest } from '@japa/api-client'
import type { ApplicationService } from '@adonisjs/core/types'
import type { Authenticators, GuardContract, GuardFactory } from '../../types.js'

declare module '@japa/api-client' {
  export interface ApiRequest {
    authData: {
      guard: string
      user: unknown
    }

    /**
     * Login a user using the default authentication
     * guard when making an API call
     */
    loginAs(user: {
      [K in keyof Authenticators]: Authenticators[K] extends GuardFactory
        ? ReturnType<Authenticators[K]> extends GuardContract<infer A>
          ? A
          : never
        : never
    }): this

    /**
     * Define the authentication guard for login
     */
    withGuard<K extends keyof Authenticators, Self extends ApiRequest>(
      this: Self,
      guard: K
    ): {
      /**
       * Login a user using a specific auth guard
       */
      loginAs(
        user: Authenticators[K] extends GuardFactory
          ? ReturnType<Authenticators[K]> extends GuardContract<infer A>
            ? A
            : never
          : never
      ): Self
    }
  }
}

/**
 * Auth API client to authenticate users when making
 * HTTP requests using the Japa API client
 */
export const authApiClient = (app: ApplicationService) => {
  ApiRequest.macro('loginAs', function (this: ApiRequest, user) {
    this.authData = {
      guard: '__default__',
      user: user,
    }
    return this
  })

  ApiRequest.macro('withGuard', function <
    K extends keyof Authenticators,
    Self extends ApiRequest,
  >(this: Self, guard: K) {
    return {
      loginAs: (user) => {
        this.authData = {
          guard,
          user: user,
        }
        return this
      },
    }
  })

  /**
   * Hook into the request and login the user
   */
  ApiClient.setup(async (request) => {
    const auth = await app.container.make('auth.manager')
    const authData = request['authData']
    if (!authData) {
      return
    }

    const client = auth.createAuthenticatorClient()
    const guard = authData.guard === '__default__' ? client.use() : client.use(authData.guard)
    const requestData = await (guard as GuardContract<unknown>).authenticateAsClient(authData.user)

    if (requestData.headers) {
      request.headers(requestData.headers)
    }
    if (requestData.session) {
      request.withSession(requestData.session)
    }
    if (requestData.cookies) {
      request.cookies(requestData.cookies)
    }
  })
}

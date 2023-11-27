/*
 * @adoniss/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/// <reference types="@japa/plugin-adonisjs" />
/// <reference types="@adonisjs/session/plugins/browser_client" />

import { RuntimeException } from '@poppinss/utils'
import type { PluginFn } from '@japa/runner/types'
import { decoratorsCollection } from '@japa/browser-client'
import type { ApplicationService } from '@adonisjs/core/types'

import debug from '../../debug.js'
import type { Authenticators, GuardContract, GuardFactory } from '../../types.js'

declare module 'playwright' {
  export interface BrowserContext {
    /**
     * Login a user using the default authentication
     * guard when using the browser context to
     * make page visits
     */
    loginAs(user: {
      [K in keyof Authenticators]: Authenticators[K] extends GuardFactory
        ? ReturnType<Authenticators[K]> extends GuardContract<infer A>
          ? A
          : never
        : never
    }): Promise<void>

    /**
     * Define the authentication guard for login
     */
    withGuard<K extends keyof Authenticators>(
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
      ): Promise<void>
    }
  }
}

export const authBrowserClient = (app: ApplicationService) => {
  const pluginFn: PluginFn = async function () {
    debug('installing auth browser client plugin')

    const auth = await app.container.make('auth.manager')

    decoratorsCollection.register({
      context(context) {
        context.withGuard = function (guardName) {
          return {
            async loginAs(user) {
              const client = auth.createAuthenticatorClient()
              const guard = client.use(guardName) as GuardContract<unknown>
              const requestData = await guard.authenticateAsClient(user)

              if (requestData.headers) {
                throw new RuntimeException(
                  `Cannot use "${guard.driverName}" guard with browser client`
                )
              }

              if (requestData.cookies) {
                debug('defining cookies with browser context %O', requestData.cookies)
                Object.keys(requestData.cookies).forEach((cookie) => {
                  context.setCookie(cookie, requestData.cookies![cookie])
                })
              }

              if (requestData.session) {
                debug('defining session with browser context %O', requestData.session)
                context.setSession(requestData.session)
              }
            },
          }
        }

        context.loginAs = async function (user) {
          const client = auth.createAuthenticatorClient()
          const guard = client.use() as GuardContract<unknown>
          const requestData = await guard.authenticateAsClient(user)

          if (requestData.headers) {
            throw new RuntimeException(`Cannot use "${guard.driverName}" guard with browser client`)
          }

          if (requestData.cookies) {
            debug('defining cookies with browser context %O', requestData.cookies)
            Object.keys(requestData.cookies).forEach((cookie) => {
              context.setCookie(cookie, requestData.cookies![cookie])
            })
          }

          if (requestData.session) {
            debug('defining session with browser context %O', requestData.session)
            context.setSession(requestData.session)
          }
        }
      },
    })
  }

  return pluginFn
}

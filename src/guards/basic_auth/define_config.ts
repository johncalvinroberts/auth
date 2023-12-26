/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { configProvider } from '@adonisjs/core'
import { RuntimeException } from '@poppinss/utils'
import type { HttpContext } from '@adonisjs/core/http'
import type { ConfigProvider } from '@adonisjs/core/types'

import type { GuardConfigProvider } from '../../auth/types.js'
import type { UserProviderContract } from '../../core/types.js'

import { BasicAuthGuard } from './guard.js'

/**
 * Helper function to configure the basic auth guard for
 * authentication.
 *
 * This method returns a config builder, which internally
 * returns a factory function to construct a guard
 * during HTTP requests.
 */
export function basicAuthGuard<UserProvider extends UserProviderContract<unknown>>(config: {
  provider: ConfigProvider<UserProvider>
}): GuardConfigProvider<(ctx: HttpContext) => BasicAuthGuard<UserProvider>> {
  return {
    async resolver(guardName, app) {
      const provider = await configProvider.resolve<UserProvider>(app, config.provider)
      if (!provider) {
        throw new RuntimeException(`Invalid user provider defined on "${guardName}" guard`)
      }

      const emitter = await app.container.make('emitter')

      /**
       * Factory function needed by Authenticator to switch
       * between guards and perform authentication
       */
      return (ctx) => {
        const guard = new BasicAuthGuard<UserProvider>(guardName, ctx, provider)
        return guard.setEmitter(emitter)
      }
    },
  }
}

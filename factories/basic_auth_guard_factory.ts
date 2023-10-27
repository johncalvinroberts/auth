/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { HttpContext } from '@adonisjs/core/http'
import {
  FactoryUser,
  TestLucidUserProvider,
  LucidUserProviderFactory,
} from './lucid_user_provider.js'
import { BasicAuthGuard } from '../src/guards/basic_auth/guard.js'
import type { UserProviderContract } from '../src/core/types.js'

/**
 * Exposes the API to create a basic auth guard for testing. Under
 * the hood configures Lucid models for looking up users
 */
export class BasicAuthGuardFactory {
  merge() {
    return this
  }

  create<
    UserProvider extends UserProviderContract<unknown> = TestLucidUserProvider<typeof FactoryUser>,
  >(ctx: HttpContext, provider?: UserProvider) {
    return new BasicAuthGuard('basic', ctx, provider || new LucidUserProviderFactory().create())
  }
}

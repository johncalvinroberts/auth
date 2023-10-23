/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { HttpContext } from '@adonisjs/core/http'

import { SessionGuard } from '../src/guards/session/guard.js'
import type {
  SessionGuardConfig,
  SessionUserProviderContract,
} from '../src/guards/session/types.js'
import {
  FactoryUser,
  TestLucidUserProvider,
  LucidUserProviderFactory,
} from './lucid_user_provider.js'

/**
 * Exposes the API to create a session guard for testing. Under
 * the hood configures Lucid models for looking up users
 */
export class SessionGuardFactory {
  #config: SessionGuardConfig = { rememberMeTokenAge: '5y' }

  merge(config: SessionGuardConfig) {
    this.#config = config
    return this
  }

  create<
    UserProvider extends SessionUserProviderContract<unknown> = TestLucidUserProvider<
      typeof FactoryUser
    >,
  >(ctx: HttpContext, provider?: UserProvider) {
    return new SessionGuard(
      'web',
      this.#config,
      ctx,
      provider || new LucidUserProviderFactory().create()
    )
  }
}

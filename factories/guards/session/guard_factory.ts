/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { HttpContext } from '@adonisjs/core/http'

import { SessionGuard } from '../../../src/guards/session/guard.js'
import type {
  SessionGuardConfig,
  SessionGuardEvents,
  SessionUserProviderContract,
} from '../../../src/guards/session/types.js'
import {
  FactoryUser,
  TestLucidUserProvider,
  LucidUserProviderFactory,
} from '../../core/lucid_user_provider.js'
import { EmitterLike } from '@adonisjs/core/types/events'
import { PROVIDER_REAL_USER } from '../../../src/auth/symbols.js'

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
  >(
    ctx: HttpContext,
    emitter: EmitterLike<SessionGuardEvents<UserProvider[typeof PROVIDER_REAL_USER]>>,
    provider?: UserProvider
  ) {
    return new SessionGuard(
      'web',
      this.#config,
      ctx,
      emitter,
      provider || new LucidUserProviderFactory().create()
    )
  }
}

/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { HttpContext } from '@adonisjs/core/http'
import { EmitterLike } from '@adonisjs/core/types/events'
import {
  FactoryUser,
  TestLucidUserProvider,
  LucidUserProviderFactory,
} from '../../core/lucid_user_provider.js'
import { PROVIDER_REAL_USER } from '../../../src/auth/symbols.js'
import type { UserProviderContract } from '../../../src/core/types.js'
import { BasicAuthGuard } from '../../../src/guards/basic_auth/guard.js'
import { BasicAuthGuardEvents } from '../../../src/guards/basic_auth/types.js'

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
  >(
    ctx: HttpContext,
    emitter: EmitterLike<BasicAuthGuardEvents<UserProvider[typeof PROVIDER_REAL_USER]>>,
    provider?: UserProvider
  ) {
    return new BasicAuthGuard(
      'basic',
      ctx,
      emitter,
      provider || new LucidUserProviderFactory().create()
    )
  }
}

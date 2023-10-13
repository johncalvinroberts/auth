/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { SessionUserProviderContract } from '../types.js'
import type { LucidAuthenticatable } from '../../core/types.js'
import { LucidUserProvider } from '../../core/user_providers/lucid.js'
import { DatabaseUserProvider } from '../../core/user_providers/database.js'

/**
 * Using lucid models to find users for session
 * auth
 */
export class LucidSessionUserProvider<UserModel extends LucidAuthenticatable>
  extends LucidUserProvider<UserModel>
  implements SessionUserProviderContract<InstanceType<UserModel>> {}

/**
 * Using database query builder to find users for
 * session auth
 */
export class DatabaseSessionUserProvider<User extends Record<string, any>>
  extends DatabaseUserProvider<User>
  implements SessionUserProviderContract<User> {}

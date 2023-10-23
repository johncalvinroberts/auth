/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { BaseLucidUserProvider } from '../../core/user_providers/lucid.js'
import { BaseDatabaseUserProvider } from '../../core/user_providers/database.js'
import type { LucidAuthenticatable, UserProviderContract } from '../../core/types.js'

/**
 * Using lucid models to find users for session
 * auth
 */
export class LucidUserProvider<UserModel extends LucidAuthenticatable>
  extends BaseLucidUserProvider<UserModel>
  implements UserProviderContract<InstanceType<UserModel>> {}

/**
 * Using database query builder to find users for
 * session auth
 */
export class DatabaseUserProvider<User extends Record<string, any>>
  extends BaseDatabaseUserProvider<User>
  implements UserProviderContract<User> {}

/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { RuntimeException } from '@poppinss/utils'

import debug from '../../auth/debug.js'
import { GuardUser } from '../guard_user.js'
import { PROVIDER_REAL_USER } from '../../auth/symbols.js'
import type {
  UserProviderContract,
  LucidAuthenticatable,
  LucidUserProviderOptions,
} from '../types.js'

/**
 * Lucid user represents a guard user, used by authentication guards
 * to perform authentication.
 */
class LucidUser<RealUser extends InstanceType<LucidAuthenticatable>> extends GuardUser<RealUser> {
  /**
   * @inheritdoc
   */
  getId(): string | number {
    const id = this.realUser.$primaryKeyValue

    /**
     * Ensure id exists
     */
    if (!id) {
      const model = this.realUser.constructor as LucidAuthenticatable
      const modelName = model.name
      const primaryKey = model.primaryKey
      throw new RuntimeException(
        `Cannot use "${modelName}" model for authentication. The value of column "${primaryKey}" is undefined or null`
      )
    }

    return id
  }

  /**
   * @inheritdoc
   */
  async verifyPassword(plainTextPassword: string): Promise<boolean> {
    return this.realUser.verifyPasswordForAuth(plainTextPassword)
  }
}

/**
 * Lucid user provider is used to lookup user for authentication
 * using a Lucid model.
 */
export abstract class BaseLucidUserProvider<UserModel extends LucidAuthenticatable>
  implements UserProviderContract<InstanceType<UserModel>>
{
  declare [PROVIDER_REAL_USER]: InstanceType<UserModel>

  /**
   * Reference to the lazily imported model
   */
  protected model?: UserModel

  constructor(
    /**
     * Lucid provider options
     */
    protected options: LucidUserProviderOptions<UserModel>
  ) {
    debug('lucid_user_provider: options %O', options)
  }

  /**
   * Imports the model from the provider, returns and caches it
   * for further operations.
   */
  protected async getModel() {
    if (this.model) {
      return this.model
    }

    const importedModel = await this.options.model()
    this.model = importedModel.default
    debug('lucid_user_provider: using model %O', this.model)
    return this.model
  }

  /**
   * Returns an instance of the query builder
   */
  protected getQueryBuilder(model: UserModel) {
    return model.query({
      client: this.options.client,
      connection: this.options.connection,
    })
  }

  /**
   * Returns an instance of the "LucidUser" that guards
   * can use for authentication
   */
  async createUserForGuard(user: InstanceType<UserModel>) {
    const model = await this.getModel()
    if (user instanceof model === false) {
      throw new RuntimeException(
        `Invalid user object. It must be an instance of the "${model.name}" model`
      )
    }

    debug('lucid_user_provider: converting user object to guard user %O', user)
    return new LucidUser(user)
  }

  /**
   * Finds a user by id using the configured model.
   */
  async findById(value: string | number): Promise<LucidUser<InstanceType<UserModel>> | null> {
    debug('lucid_user_provider: finding user by id %s', value)

    const model = await this.getModel()
    const user = await model.find(value, {
      client: this.options.client,
      connection: this.options.connection,
    })

    if (!user) {
      return null
    }

    return new LucidUser(user)
  }

  /**
   * Finds a user using one of the pre-configured unique
   * ids, via the configured model.
   */
  async findByUid(value: string | number): Promise<LucidUser<InstanceType<UserModel>> | null> {
    const query = this.getQueryBuilder(await this.getModel())
    this.options.uids.forEach((uid) => query.orWhere(uid, value))

    debug(
      'lucid_user_provider: finding user by uids, uids: %O, value: %s',
      this.options.uids,
      value
    )

    const user = await query.limit(1).first()
    if (!user) {
      return null
    }

    return new LucidUser(user)
  }
}

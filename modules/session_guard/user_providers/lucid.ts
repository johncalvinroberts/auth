/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Hash } from '@adonisjs/core/hash'
import { RuntimeException } from '@poppinss/utils'

import debug from '../debug.js'
import { PROVIDER_REAL_USER } from '../../../src/symbols.js'
import type {
  GuardUser,
  LucidAuthenticatable,
  SessionUserProviderContract,
  SessionLucidUserProviderOptions,
} from '../types.js'

/**
 * Lucid user represents a guard user, used by authentication guards
 * to perform authentication.
 */
class LucidUser<RealUser extends InstanceType<LucidAuthenticatable>>
  implements GuardUser<RealUser>
{
  constructor(public realUser: RealUser) {}

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
   * Returns the original user by reference
   */
  getOriginal(): RealUser {
    return this.realUser
  }
}

/**
 * Implementation of session user provider that uses lucid models
 * to find user and remember me tokens
 */
export class SessionLucidUserProvider<UserModel extends LucidAuthenticatable>
  implements SessionUserProviderContract<InstanceType<UserModel>>
{
  declare [PROVIDER_REAL_USER]: InstanceType<UserModel>

  /**
   * Reference to the lazily imported model
   */
  protected model?: UserModel

  constructor(
    /**
     * Hasher is used to verify plain text passwords
     */
    protected hasher: Hash,

    /**
     * Lucid provider options
     */
    protected options: SessionLucidUserProviderOptions<UserModel>
  ) {}

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
    debug('lucid_user_provider: using model [class %s]', this.model.name)
    return this.model
  }

  /**
   * Returns an instance of the query builder
   */
  protected getQueryBuilder(model: UserModel) {
    return model.query({
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
  async findById(value: string | number): Promise<GuardUser<InstanceType<UserModel>> | null> {
    debug('lucid_user_provider: finding user by id %s', value)

    const model = await this.getModel()
    const user = await model.find(value, {
      connection: this.options.connection,
    })

    if (!user) {
      return null
    }

    return this.createUserForGuard(user)
  }

  /**
   * Finds the user by uid and returns an instance of the guard user
   */
  async findByUid(uid: string | number): Promise<GuardUser<InstanceType<UserModel>> | null> {
    const model = await this.getModel()

    /**
     * Use custom lookup method when defined on the model.
     */
    if ('getUserForAuth' in model && typeof model.getUserForAuth === 'function') {
      debug('lucid_user_provider: using getUserForAuth method on "[class %s]"', model.name)

      const user = await model.getUserForAuth(this.options.uids, uid)
      if (!user) {
        return null
      }

      return this.createUserForGuard(user)
    }

    /**
     * Self query
     */
    debug('lucid_user_provider: finding user by uids: %O, value: %s', this.options.uids, uid)
    const query = this.getQueryBuilder(model)
    this.options.uids.forEach((uidColumn) => query.orWhere(uidColumn, uid))

    const user = await query.limit(1).first()
    if (!user) {
      return null
    }

    return this.createUserForGuard(user)
  }

  /**
   * Find a user by uid and verify their password. This method prevents
   * timing attacks.
   */
  async verifyCredentials(
    uid: string | number,
    password: string
  ): Promise<GuardUser<InstanceType<UserModel>> | null> {
    const user = await this.findByUid(uid)

    /**
     * Hashing the password to prevent timing attacks.
     */
    if (!user) {
      await this.hasher.make(password)
      return null
    }

    /**
     * Check the password hash exists on the model or thrown
     * an error
     */
    const passwordHash = user.getOriginal()[this.options.passwordColumnName]
    if (!passwordHash) {
      throw new RuntimeException(
        `Cannot verify password during login. The value of column "${this.options.passwordColumnName}" is undefined or null`
      )
    }

    /**
     * Verify password
     */
    if (await this.hasher.verify(passwordHash as string, password)) {
      return user
    }

    /**
     * Invalid password, return null
     */
    return null
  }
}

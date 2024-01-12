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
import { RememberMeToken } from '../remember_me_token.js'
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
   * Returns the remember me model associated with
   * user model
   */
  protected async getRememberMeModel() {
    const model = await this.getModel()
    if (!model.rememberMeTokens) {
      throw new RuntimeException(
        `Cannot perist remember me token using "${model.name}" model. Make sure to use "withRememberMeTokens" mixin`
      )
    }

    return model.rememberMeTokens
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
  async findById(
    value: string | number | BigInt
  ): Promise<GuardUser<InstanceType<UserModel>> | null> {
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
    if (typeof model.getUserForAuth === 'function') {
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

  /**
   * Persists the remember token to the database using the
   * model.rememberMeTokens property
   */
  async createRememberMeToken(token: RememberMeToken): Promise<void> {
    const rememberMeModel = await this.getRememberMeModel()
    await rememberMeModel.create({
      userId: token.userId,
      createdAt: token.createdAt,
      updatedAt: token.createdAt,
      expiresAt: token.expiresAt,
      guard: token.guard,
      hash: token.hash,
      series: token.series,
      type: token.type,
    })
  }

  /**
   * Finds a remember me token for a user by the series.
   * Uses model.rememberMeTokens property
   */
  async findRememberMeTokenBySeries(series: string): Promise<RememberMeToken | null> {
    const rememberMeModel = await this.getRememberMeModel()
    const token = await rememberMeModel.query().where('series', series).limit(1).first()
    if (!token) {
      return null
    }

    const rememberMeToken = RememberMeToken.createFromPersisted({
      createdAt: typeof token.createdAt === 'number' ? new Date(token.createdAt) : token.createdAt,
      updatedAt: typeof token.updatedAt === 'number' ? new Date(token.updatedAt) : token.updatedAt,
      expiresAt: typeof token.expiresAt === 'number' ? new Date(token.expiresAt) : token.expiresAt,
      guard: token.guard,
      hash: token.hash,
      series: token.series,
      userId: token.userId,
    })

    if (rememberMeToken.isExpired() || token.type !== rememberMeToken.type) {
      return null
    }

    return rememberMeToken
  }

  /**
   * Updates the remember me token with new attributes. Uses
   * model.rememberMeTokens property
   */
  async recycleRememberMeToken(token: RememberMeToken): Promise<void> {
    const rememberMeModel = await this.getRememberMeModel()
    await rememberMeModel.query().where('series', token.series).update({
      hash: token.hash,
      updatedAt: token.updatedAt,
      expiresAt: token.expiresAt,
    })
  }

  /**
   * Deletes an existing remember me token. Uses model.rememberMeTokens
   * property.
   */
  async deleteRememberMeTokenBySeries(series: string): Promise<void> {
    const rememberMeModel = await this.getRememberMeModel()
    await rememberMeModel.query().where('series', series).del()
  }
}

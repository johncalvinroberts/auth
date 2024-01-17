/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Secret } from '@adonisjs/core/helpers'
import { RuntimeException } from '@adonisjs/core/exceptions'
import { PROVIDER_REAL_USER } from '../../../src/symbols.js'
import type {
  AccessTokensGuardUser,
  AccessTokensLucidUserProviderOptions,
  AccessTokensUserProviderContract,
  LucidTokenable,
} from '../types.js'
import { AccessToken } from '../access_token.js'

/**
 * Uses a lucid model to verify access tokens and find a user during
 * authentication
 */
export class AccessTokensLucidUserProvider<
  TokenableProperty extends string,
  UserModel extends LucidTokenable<TokenableProperty>,
> implements AccessTokensUserProviderContract<InstanceType<UserModel>>
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
    protected options: AccessTokensLucidUserProviderOptions<TokenableProperty, UserModel>
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
    return this.model
  }

  /**
   * Returns the tokens provider associated with the user model
   */
  protected async getTokensProvider() {
    const model = await this.getModel()

    if (!model[this.options.tokens]) {
      throw new RuntimeException(
        `Cannot use "${model.name}" for verifying access tokens. Make sure to assign a token provider to the model.`
      )
    }

    return model[this.options.tokens]
  }

  /**
   * Creates an adapter user for the guard
   */
  async createUserForGuard(
    user: InstanceType<UserModel>
  ): Promise<AccessTokensGuardUser<InstanceType<UserModel>>> {
    const model = await this.getModel()
    if (user instanceof model === false) {
      throw new RuntimeException(
        `Invalid user object. It must be an instance of the "${model.name}" model`
      )
    }

    return {
      getId() {
        /**
         * Ensure user has a primary key
         */
        if (!user.$primaryKeyValue) {
          throw new RuntimeException(
            `Cannot use "${model.name}" model for authentication. The value of column "${model.primaryKey}" is undefined or null`
          )
        }

        return user.$primaryKeyValue
      },
      getOriginal() {
        return user
      },
    }
  }

  /**
   * Create a token for a given user
   */
  async createToken(
    user: InstanceType<UserModel>,
    abilities?: string[] | undefined,
    options?: {
      name?: string
      expiresIn?: string | number
    }
  ): Promise<AccessToken> {
    const model = await this.getModel()
    if (user instanceof model === false) {
      throw new RuntimeException(
        `Invalid user object. It must be an instance of the "${model.name}" model`
      )
    }

    const tokensProvider = await this.getTokensProvider()
    return tokensProvider.create(user, abilities, options)
  }

  /**
   * Finds a user by their primary key value
   */
  async findById(
    tokenableId: string | number | BigInt
  ): Promise<AccessTokensGuardUser<InstanceType<UserModel>> | null> {
    const model = await this.getModel()
    const user = await model.find(tokenableId)

    if (!user) {
      return null
    }

    return this.createUserForGuard(user)
  }

  /**
   * Verifies a publicly shared access token and returns an
   * access token for it.
   */
  async verifyToken(tokenValue: Secret<string>): Promise<AccessToken | null> {
    const tokensProvider = await this.getTokensProvider()
    return tokensProvider.verify(tokenValue)
  }
}

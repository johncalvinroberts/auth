/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { Secret } from '@adonisjs/core/helpers'
import type { LucidModel } from '@adonisjs/lucid/types/model'

import { AccessToken } from '../access_token.js'
import type {
  AccessTokenDbColumns,
  AccessTokensProviderContract,
  DbAccessTokensProviderOptions,
} from '../types.js'

/**
 * DbAccessTokensProvider uses lucid database service to fetch and
 * persist tokens for a given user.
 *
 * The user must be an instance of the associated user model.
 */
export class DbAccessTokensProvider<TokenableModel extends LucidModel>
  implements AccessTokensProviderContract
{
  /**
   * Create tokens provider instance for a given Lucid model
   */
  static forModel<TokenableModel extends LucidModel>(
    model: DbAccessTokensProviderOptions<TokenableModel>['tokenableModel'],
    options?: Omit<DbAccessTokensProviderOptions<TokenableModel>, 'tokenableModel'>
  ) {
    return new DbAccessTokensProvider<TokenableModel>({ tokenableModel: model, ...(options || {}) })
  }

  /**
   * A unique type for the value. The type is used to identify a
   * bucket of tokens within the storage layer.
   *
   * Defaults to auth_token
   */
  protected type: string

  /**
   * A unique prefix to append to the publicly shared token value.
   *
   * Defaults to oat
   */
  protected prefix: string

  /**
   * Database table to use for querying access tokens
   */
  protected table: string

  /**
   * The length for the token secret. A secret is a cryptographically
   * secure random string.
   */
  protected tokenSecretLength: number

  constructor(protected options: DbAccessTokensProviderOptions<TokenableModel>) {
    this.table = options.table || 'auth_access_tokens'
    this.tokenSecretLength = options.tokenSecretLength || 40
    this.type = options.type || 'auth_token'
    this.prefix = options.prefix || 'oat'
  }

  protected async getDb() {
    const model = this.options.tokenableModel
    return model.$adapter.query(model).client
  }

  /**
   * Create a token for a user
   */
  async create(
    user: InstanceType<TokenableModel>,
    abilities: string[] = ['*'],
    expiresIn?: string | number
  ) {
    const queryClient = await this.getDb()
    const transientToken = AccessToken.createTransientToken(
      user.$primaryKeyValue!,
      this.tokenSecretLength,
      expiresIn || this.options.expiresIn
    )

    const dbRow: Omit<AccessTokenDbColumns, 'id'> = {
      tokenable_id: transientToken.userId,
      type: this.type,
      hash: transientToken.hash,
      abilities: JSON.stringify(abilities),
      created_at: new Date(),
      updated_at: new Date(),
      last_used_at: null,
      expires_at: transientToken.expiresAt || null,
    }

    const [id] = await queryClient.table(this.table).insert(dbRow)
    return new AccessToken({
      identifier: id,
      tokenableId: dbRow.tokenable_id,
      type: dbRow.type,
      prefix: this.prefix,
      secret: transientToken.secret,
      hash: dbRow.hash,
      abilities: JSON.parse(dbRow.abilities),
      createdAt: dbRow.created_at,
      updatedAt: dbRow.updated_at,
      lastUsedAt: dbRow.last_used_at,
      expiresAt: dbRow.expires_at,
    })
  }

  /**
   * Find a token for a user by the token id
   */
  async find(user: InstanceType<TokenableModel>, identifier: string) {
    const queryClient = await this.getDb()
    const dbRow = await queryClient
      .query<AccessTokenDbColumns>()
      .from(this.table)
      .where({ id: identifier, tokenable_id: user.$primaryKeyValue, type: this.type })
      .limit(1)
      .first()

    if (!dbRow) {
      return null
    }

    return new AccessToken({
      identifier: dbRow.id,
      tokenableId: dbRow.tokenable_id,
      type: dbRow.type,
      hash: dbRow.hash,
      abilities: JSON.parse(dbRow.abilities),
      createdAt: dbRow.created_at,
      updatedAt: dbRow.updated_at,
      lastUsedAt: dbRow.last_used_at,
      expiresAt: dbRow.expires_at,
    })
  }

  /**
   * Returns all the tokens a given user
   */
  async all(user: InstanceType<TokenableModel>) {
    const queryClient = await this.getDb()
    const dbRows = await queryClient
      .query<AccessTokenDbColumns>()
      .from(this.table)
      .where({ tokenable_id: user.$primaryKeyValue, type: this.type })
      .exec()

    if (!dbRows) {
      return null
    }

    return dbRows.map((dbRow) => {
      return new AccessToken({
        identifier: dbRow.id,
        tokenableId: dbRow.tokenable_id,
        type: dbRow.type,
        hash: dbRow.hash,
        abilities: JSON.parse(dbRow.abilities),
        createdAt: dbRow.created_at,
        updatedAt: dbRow.updated_at,
        lastUsedAt: dbRow.last_used_at,
        expiresAt: dbRow.expires_at,
      })
    })
  }

  /**
   * Verifies a publicly shared access token and returns an
   * access token for it.
   *
   * Returns null when unable to verify the token or find it
   * inside the storage
   */
  async verify(tokenValue: Secret<string>) {
    const decodedToken = AccessToken.decode(this.prefix, tokenValue.release())
    if (!decodedToken) {
      return null
    }

    const db = await this.getDb()
    const dbRow = await db
      .query<AccessTokenDbColumns>()
      .from(this.table)
      .where({ id: decodedToken.identifier, type: this.type })
      .limit(1)
      .first()

    if (!dbRow) {
      return null
    }

    const accessToken = new AccessToken({
      identifier: dbRow.id,
      tokenableId: dbRow.tokenable_id,
      type: dbRow.type,
      hash: dbRow.hash,
      abilities: JSON.parse(dbRow.abilities),
      createdAt: dbRow.created_at,
      updatedAt: dbRow.updated_at,
      lastUsedAt: dbRow.last_used_at,
      expiresAt: dbRow.expires_at,
    })

    /**
     * Ensure the token secret matches the token hash
     */
    if (!accessToken.verify(decodedToken.secret) || accessToken.isExpired()) {
      return null
    }

    return accessToken
  }
}
